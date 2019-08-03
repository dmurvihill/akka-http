package akka.http.scaladsl.coding

import java.nio.charset.StandardCharsets
import java.nio.{ ByteBuffer, ByteOrder, CharBuffer }
import java.security.SecureRandom

import akka.http.scaladsl.coding.KeyIdEncoding.{ InvalidKeyId, ValidKeyId }
import akka.http.scaladsl.model.HttpMessage
import akka.http.scaladsl.model.headers.HttpEncoding
import akka.stream.Attributes
import akka.stream.impl.io.ByteStringParser
import akka.stream.impl.io.ByteStringParser.{ ByteReader, ParseResult, ParseStep }
import akka.stream.stage.GraphStageLogic
import akka.util.ByteString
import javax.crypto.spec.{ GCMParameterSpec, SecretKeySpec }
import javax.crypto.{ AEADBadTagException, Cipher, Mac, SecretKey }

/**
  * Provides the aes128gcm content encoding
  *
  * Reference: RFC 8188
  *
  * WARNING: Use of Akka HTTP's default message filter is not
  * recommended, since
  * that filter only encodes successful responses; if you do use the
  * default message filter, be aware that any error responses you send
  * back will not be encrypted.
  *
  * WARNING: NEVER OVERRIDE THE "saltOverride" PARAMETER IN PRODUCTION.
  *
  * If the same salt is ever reused for _any_ message, the encryption
  * key can be trivially recovered. The 'saltOverride' parameter is
  * intended for verifying the cipher against published test vectors
  * _only_.
 */
class Aes128GcmEncoding(
  override val messageFilter: HttpMessage => Boolean,
  encodingKey:                Array[Byte],
  encodingKeyId:              String,
  getDecodingKey:             String => IndexedSeq[Byte],
  saltOverride: Option[IndexedSeq[Byte]] = None,
) extends Coder with StreamDecoder {

  override def encoding: HttpEncoding = HttpEncoding.custom("aes128gcm")

  override def newCompressor: Compressor = {
    new Aes128GcmEncoder(encodingKey, encodingKeyId,
      Aes128GcmEncoding.defaultRecordSize, saltOverride)
  }

  override def newDecompressorStage(maxBytesPerChunk: Int): () => Aes128GcmDecoder =
    () => new Aes128GcmDecoder(getDecodingKey, maxBytesPerChunk)
}

object Aes128GcmEncoding extends ByteRepresentationsUtil {
  val maxRecords: BigInt = (BigInt(1) << 96) - 1 // Sequence numbers are 96 bits
  val defaultRecordSize: Long = 65535
  val saltLength: Int = 16
  val authTagLength: Int = 16
  val recordSizeLength: Int = 4
  val idLengthLength = 1
  val minHeaderLength: Int = saltLength + recordSizeLength + idLengthLength
  val minRecordPad = 1
  def headerLength(idLength: Byte): Int = minHeaderLength + idLength
}

case class GcmParams(key: IndexedSeq[Byte], salt: IndexedSeq[Byte], recordSize: Long) {
  val minRecordSize: Long = 18
  val maxRecordSize: Long = 0xffffffffL // 32-bit unsigned int
  assert(
    minRecordSize <= recordSize,
    s"record size $recordSize is less than the minimum ($minRecordSize)")
  require(
    recordSize <= maxRecordSize,
    s"record size $recordSize exceeds the max record size ($maxRecordSize)")
  def maxRecordPlaintextLength: Long =
    recordSize - Aes128GcmEncoding.authTagLength - Aes128GcmEncoding.minRecordPad
}

case class GcmState(params: GcmParams, contentEncryptionKey: SecretKey,
                    firstIv: Array[Byte], seqNo: BigInt) {
  require(
    seqNo < Aes128GcmEncoding.maxRecords,
    s"Maximum number of records (2^96 - 1) exceeded")
}

class Aes128GcmDecoder(
  getKey:           String => IndexedSeq[Byte],
  maxBytesPerChunk: Int                        = Decoder.MaxBytesPerChunkDefault)
  extends ByteStringParser[ByteString] with GcmEncodingCryptoPrimitives {

  override def initialAttributes: Attributes = Attributes.name("Aes128GcmDecoder")

  override def createLogic(attr: Attributes): GraphStageLogic = new ParsingLogic {

    case object ReadHeader extends ParseStep[ByteString] {
      override def canWorkWithPartialData: Boolean = false
      override def onTruncation(): Unit = throw new IllegalStateException("Truncated aes128gcm stream")

      override def parse(reader: ByteReader): ParseResult[ByteString] = {
        val salt = reader.take(16)
        val recordSize = fromUint32ByteArray(reader.take(4).toArray, ByteOrder.BIG_ENDIAN)
        val idLength = fromUint8ByteArray(reader.take(1).toArray)
        val key = getKey(KeyIdEncoding.decode(reader.take(idLength).toArray) match {
          case ValidKeyId(keyId) => keyId
          case InvalidKeyId(msg) => throw new IllegalArgumentException(msg)
        })
        val pseudoRandomKey = getPseudoRandomKey(salt.toArray, key.toArray)
        ParseResult(
          None,
          Decrypt(
            GcmState(
              GcmParams(key, salt, recordSize),
              deriveContentEncryptionKey(pseudoRandomKey),
              getFirstIV(pseudoRandomKey),
              0
            )
          )
        )
      }
    }

    case class Decrypt(state: GcmState) extends ParseStep[ByteString] {
      override def canWorkWithPartialData: Boolean = false
      override def onTruncation(): Unit = throw new IllegalStateException("Truncated aes128gcm stream")

      /** Decrypt the next record */
      override def parse(reader: ByteReader): ParseResult[ByteString] = {
        val encryptedRecord: ByteString = takeLong(reader, state.params.recordSize)
        val nonce = deriveNonce(state.firstIv, state.seqNo)
        val padded = aes128Decode(encryptedRecord.toArray, state.contentEncryptionKey, nonce)
        val paddingDelimiterIndex = padded.lastIndexWhere(_ != 0x00)
        val decryptedRecord = ByteString.fromArray(padded.slice(0, paddingDelimiterIndex))
        padded(paddingDelimiterIndex) match {
          case 0x01 => ParseResult(
            Some(decryptedRecord),
            Decrypt(state.copy(seqNo = state.seqNo + 1)),
            acceptUpstreamFinish = false
          )
          case 0x02 => ParseResult(Some(decryptedRecord), Finished)
          case -1 =>
            throw new IllegalArgumentException(s"Unable to decode request: record ${state.seqNo} is all zeroes")
          case _ =>
            throw new IllegalArgumentException(s"Unable to decode request: record ${state.seqNo} has illegal " +
              s"padding delimiter ${padded(paddingDelimiterIndex)} at offset $paddingDelimiterIndex. Should be 0x02 in " +
              s"the last record, 0x01 in other records.")
        }
      }

      case object Finished extends ParseStep[Nothing] {
        override def parse(reader: ByteReader) =
          throw new IllegalStateException("Received additional records after the final record.")
      }
    }

    private def takeLong(reader: ByteReader, n: Long): ByteString = {
      if (n < Int.MaxValue) reader.take(n.toInt)
      else reader.take(Int.MaxValue) ++ takeLong(reader, n - Int.MaxValue)
    }

    startWith(ReadHeader)
  }
}

/** Encoder for AES
  *
  * WARNING: NEVER OVERRIDE THE "saltOverride" PARAMETER IN PRODUCTION.
  *
  * If the same salt is ever reused for _any_ message, the encryption
  * key can be trivially recovered. The 'saltOverride' parameter is
  * intended for verifying the cipher against published test vectors
  * _only_.
  */
class Aes128GcmEncoder(key: IndexedSeq[Byte],
                       keyId: String,
                       recordSize: Long = Aes128GcmEncoding.defaultRecordSize,
                       saltOverride: Option[IndexedSeq[Byte]] = None)
  extends Compressor with GcmEncodingCryptoPrimitives with ByteRepresentationsUtil {

  private val salt: Array[Byte] = saltOverride.map(_.toArray).getOrElse(genSalt())
  require(salt.length == 16)
  private val params: GcmParams = GcmParams(key, salt, recordSize)

  private val keyIdBytes = KeyIdEncoding.encode(keyId)
  assert(keyIdBytes.length <= maxUnsignedByte)
  private val pseudoRandomKey = getPseudoRandomKey(params.salt.toArray, params.key.toArray)

  private var state: GcmState = GcmState(params, deriveContentEncryptionKey(pseudoRandomKey), getFirstIV(pseudoRandomKey), 0)
  private var inputBuffer: ByteString = ByteString.empty
  private var isHeaderEmitted = false
  private var isFinished = false

  override def compress(input: ByteString): ByteString = {
    ensureOpen()
    inputBuffer = inputBuffer ++ input
    val recordsOut = if (input.length >= params.maxRecordPlaintextLength)
      encryptRecord(takeLong(params.maxRecordPlaintextLength)) ++ compress(ByteString())
    else ByteString()
    state = state.copy(seqNo = state.seqNo + 1)
    emitHeaderIfNeeded() ++ recordsOut
  }

  override def flush(): ByteString = {
    ensureOpen()
    require(inputBuffer.isEmpty, "Cannot flush in the middle of a record." +
      "If this is the last record, call finish() intsead.")
    emitHeaderIfNeeded()
  }

  override def finish(): ByteString = {
    ensureOpen()
    isFinished = true
    // TODO this can cause us to have empty records and that's not efficient.
    // Maybe we can somehow LBYL to see which record is the last.
    emitHeaderIfNeeded() ++ encryptRecord(inputBuffer)
  }

  private def encryptRecord(raw: ByteString): ByteString = {
    assert(raw.length <= params.maxRecordPlaintextLength)
    // Only the final record can be smaller than the record size
    assert(raw.length == params.maxRecordPlaintextLength || isFinished)
    val toLength = params.recordSize - Aes128GcmEncoding.authTagLength
    assert(toLength < Int.MaxValue) // required by pad()
    val padded = pad(raw, toLength)
    val nonce = deriveNonce(state.firstIv, state.seqNo)
    ByteString(aes128Encode(padded, state.contentEncryptionKey, nonce))
  }

  private def pad(plain: IndexedSeq[Byte], toLength: Long): Array[Byte] = {
    assert(toLength < Int.MaxValue) // Array.length is an Int
    assert(plain.length < toLength)
    val toLengthInt = toLength.toInt
    val padded = new Array[Byte](toLengthInt)
    val delimIndex = toLengthInt - (toLengthInt - plain.length)
    for (i <- 0 until delimIndex) {
      padded(i) = plain(i)
    }
    padded(delimIndex) = if (isFinished) 0x02 else 0x01
    for (i <- delimIndex + 1 until toLengthInt) {
      padded(i) = 0x00.toByte
    }
    padded
  }

  override def compressAndFlush(input: ByteString): ByteString = compress(input) ++ flush()

  override def compressAndFinish(input: ByteString): ByteString = compress(input) ++ finish()

  private def takeLong(n: Long): ByteString = {
    if (n == 0) ByteString.empty
    else {
      val numToTake: Int = if (n <= Int.MaxValue) n.toInt else Int.MaxValue
      val out = inputBuffer.take(numToTake)
      inputBuffer = inputBuffer.drop(numToTake)
      out ++ takeLong(n - numToTake)
    }
  }

  private def emitHeaderIfNeeded(): ByteString = {
    if (isHeaderEmitted) ByteString.empty
    else {
      emitHeader()
    }
  }

  private def emitHeader(): ByteString = {
    val outHeader = buildHeader
    isHeaderEmitted = true
    outHeader
  }

  private def buildHeader: ByteString = {
    val outBuffer: ByteBuffer = ByteBuffer.allocate(
      Aes128GcmEncoding.headerLength(keyIdBytes.length.toByte))
    outBuffer.order(ByteOrder.BIG_ENDIAN)
    assert(keyIdBytes.length <= maxUnsignedByte)
    outBuffer.put(params.salt.toArray)
    outBuffer.put(toUint32ByteArray(params.recordSize, outBuffer.order))
    outBuffer.put(toUint8ByteArray(keyIdBytes.length.toShort))
    outBuffer.put(keyIdBytes)
    ByteString(outBuffer)
  }

  private def ensureOpen(): Unit = if (isFinished) {
    throw new IllegalStateException("Encoder already finished")
  }
}

trait GcmEncodingCryptoPrimitives extends ByteRepresentationsUtil {
  private val aes = Cipher.getInstance("AES/GCM/NoPadding")
  private val hmac = Mac.getInstance("HmacSHA256")
  private val rand = new SecureRandom()

  private val cekInfo: Array[Byte] = "Content-Encoding: aes128gcm".getBytes(StandardCharsets.US_ASCII) ++ Array[Byte](0x00, 0x01)
  private val nonceInfo: Array[Byte] = "Content-Encoding: nonce".getBytes(StandardCharsets.US_ASCII) ++ Array[Byte](0x00, 0x01)

  /**
   * Generate a salt for a GCM operation
   *
   * WARNING: DO NOT REUSE THIS SALT ACROSS MESSAGES. The secrecy of all messages with the same salt and IKM will be
   * compromised, as will the integrity of all subsequent messages that use the same IKM.
   *
   * @return 16-byte salt
   */
  protected def genSalt(): Array[Byte] = {
    val salt = new Array[Byte](Aes128GcmEncoding.saltLength)
    rand.nextBytes(salt)
    salt
  }

  protected def getPseudoRandomKey(salt: Array[Byte], inputKeyingMaterial: Array[Byte]): Array[Byte] = {
    assert(salt.length == Aes128GcmEncoding.saltLength)
    hmacSha256(salt, inputKeyingMaterial) // Used in both the nonce and the CEK
  }

  /**
   * Derive an ephemeral key for an AES-128-GCM message
   * Reference: RFC 8188, section 2.2
   *
   * @param pseudoRandomKey IKM mixed with salt -- DO NOT REUSE ACROSS MESSAGES.
   * @return 16-octet content encryption key for a message
   */
  protected def deriveContentEncryptionKey(pseudoRandomKey: Array[Byte]): SecretKey = {
    val keyBytes = hmacSha256(pseudoRandomKey, cekInfo).slice(0, 16)
    new SecretKeySpec(keyBytes, "AES")
  }

  protected def getFirstIV(pseudoRandomKey: Array[Byte]): Array[Byte] = {
    val iv = hmacSha256(pseudoRandomKey, nonceInfo).slice(0, 12)
    iv
  }

  /**
   * Derive a nonce for an AES-128-GCM calculation
   *
   * Reference: RFC 8188, section 2.3
   *
   * @param firstIV        IV to use for the first record -- DO NOT REUSE ACROSS RECORDS.
   * @param sequenceNumber 12-octet integer representing the record number
   * @return 12-octet encryption nonce for a record
   */
  protected def deriveNonce(firstIV: Array[Byte], sequenceNumber: BigInt): Array[Byte] = {
    val nonce = (firstIV zip toUnsignedByteArray(sequenceNumber, 12)) map (a => (a._1 ^ a._2).toByte)
    nonce
  }

  /** Call the Java crypto libraries to produce an HMAC */
  protected def hmacSha256(key: Array[Byte], info: Array[Byte]): Array[Byte] = {
    hmac.init(new SecretKeySpec(key, "HmacSHA256"))
    hmac.doFinal(info)
  }

  /** Call the Java crypto libraries to decode a cipher block */
  protected def aes128Decode(ciphertext: Array[Byte], key: SecretKey, initializationVector: Array[Byte]): Array[Byte] = {
    val params = new GCMParameterSpec(Aes128GcmEncoding.authTagLength * 8, initializationVector)
    aes.init(Cipher.DECRYPT_MODE, key, params)
    aes.updateAAD(Array.empty[Byte])
    try aes.doFinal(ciphertext)
    catch {
      case _: AEADBadTagException =>
        throw new IllegalArgumentException("Invalid authentication tag")
    }
  }

  /** Call the Java crypto libraries to decode a cipher block */
  protected def aes128Encode(plaintext: Array[Byte], key: SecretKey, initializationVector: Array[Byte]): Array[Byte] = {
    val params = new GCMParameterSpec(Aes128GcmEncoding.authTagLength * 8, initializationVector)
    aes.init(Cipher.ENCRYPT_MODE, key, params)
    aes.updateAAD(Array.empty[Byte])
    aes.doFinal(plaintext)
  }

}

object KeyIdEncoding extends ByteRepresentationsUtil {
  private val utf8Decoder = StandardCharsets.UTF_8.newDecoder()
  def decode(encoded: Array[Byte]): ReadKeyIdResult = {
    assert(encoded.length <= 255)
    val buf = CharBuffer.allocate(Math.ceil(encoded.length * utf8Decoder.maxCharsPerByte).toInt)
    val result1 = utf8Decoder.decode(ByteBuffer.wrap(encoded), buf, true)
    val result2 = utf8Decoder.flush(buf)
    val result = if (result1.isOverflow || result2.isOverflow) {
      // This condition is not expected since we allocated the maximum buffer space we could need
      throw new IllegalStateException(s"Unexpected overflow when reading key ID ${toHexString(encoded)}")
    } else if (result1.isMalformed || result2.isMalformed) {
      InvalidKeyId(s"Malformed key ID ${toHexString(encoded)}; must be valid UTF-8")
    } else if (result1.isUnmappable || result2.isUnmappable) {
      InvalidKeyId(s"key ID ${toHexString(encoded)} contains unmappable code points; should be valid UTF-8")
    } else {
      ValidKeyId(buf.toString)
    }
    utf8Decoder.reset()
    result
  }

  def encode(keyId: String): Array[Byte] = {
    val outBuffer = StandardCharsets.UTF_8.encode(keyId)
    val outArray = new Array[Byte](outBuffer.limit)
    outBuffer.get(outArray)
    outArray
  }

  private[akka] sealed trait ReadKeyIdResult
  private[akka] case class ValidKeyId(keyId: String) extends ReadKeyIdResult
  private[akka] case class InvalidKeyId(msg: String) extends ReadKeyIdResult
}

trait ByteRepresentationsUtil {

  protected final val maxUnsignedByte = 0xff
  protected final val maxUnsignedInt = 0xffffffffL

  /**
   * Convert a positive big integer to an unsigned byte array
   *
   * The result is a twos-complement representation of the number, in network
   * byte order (most significant byte at index 0), and the number is padded
   * with zeroes to exactly len bytes.
   *
   * @param i   integer to represent
   * @param len size of output array
   * @return Zero-padded unsigned integer representation
   */
  protected def toUnsignedByteArray(i: BigInt, len: Int): Array[Byte] = {
    val maxInt = BigInt(2).pow(len * 8) - 1
    assert(i <= maxInt, s"Integer is too large to represent in $len bytes")
    assert(i >= 0, s"Unexpected negative integer $i")
    val unpadded = i.toByteArray
    if (unpadded.length > len) {
      /* This happens if i is more than half the max int. In that case the sign
      bit is the final bit in the first byte, and the MSB is the first bit in
      the second byte. We already know that this first byte is all zeroes since
      we checked the sign, so we simply trim it off. */
      unpadded.slice(from = 1, until = unpadded.length + 1)
    } else {
      val out = new Array[Byte](len)
      for (i <- 0 until (len - unpadded.length)) {
        out(i) = 0x00
      }
      for (i <- (len - unpadded.length) until len) {
        out(i) = unpadded(i - len + unpadded.length)
      }
      out
    }
  }

  protected def fromUint8ByteArray(i: Array[Byte]): Short = {
    require(i.length == 1)
    (i(0) & 0xFF).toShort
  }

  protected def fromUint32ByteArray(i: Array[Byte], byteOrder: ByteOrder): Long = {
    require(i.length == 4)
    byteOrder match {
      case ByteOrder.BIG_ENDIAN =>
        ((i(0) & 0xffL) << 24) |
          ((i(1) & 0xffL) << 16) |
          ((i(2) & 0xffL) << 8) |
          ((i(3) & 0xffL) << 0)
      case ByteOrder.LITTLE_ENDIAN =>
        ((i(0) & 0xffL) << 0) &
          ((i(1) & 0xffL) << 8) &
          ((i(2) & 0xffL) << 16) &
          ((i(3) & 0xffL) << 24)

    }
  }

  protected def toUint32ByteArray(i: Long, byteOrder: ByteOrder): Array[Byte] = {
    require(0 <= i)
    require(i <= maxUnsignedInt)
    val out = new Array[Byte](4)
    byteOrder match {
      case ByteOrder.BIG_ENDIAN =>
        out(0) = ((i & 0xff000000L) >>> 24).toByte
        out(1) = ((i & 0x00ff0000L) >>> 16).toByte
        out(2) = ((i & 0x0000ff00L) >>> 8).toByte
        out(3) = ((i & 0x000000ffL) >>> 0).toByte
      case ByteOrder.LITTLE_ENDIAN =>
        out(0) = ((i & 0x000000ffL) >>> 0).toByte
        out(1) = ((i & 0x0000ff00L) >>> 8).toByte
        out(2) = ((i & 0x00ff0000L) >>> 16).toByte
        out(3) = ((i & 0xff000000L) >>> 24).toByte
    }
    out
  }

  protected def toUint8ByteArray(i: Short): Array[Byte] = {
    require(0 <= i)
    require(i <= maxUnsignedByte)
    val out = new Array[Byte](1)
    out(0) = (i & 0xff).toByte
    out
  }

  // Courtesy of Alvin Alexander
  protected def toHexString(bytes: Seq[Byte]): String = {
    val sb = new StringBuilder
    for (b <- bytes) {
      sb.append(String.format("%02x", Byte.box(b)))
    }
    sb.toString
  }
}