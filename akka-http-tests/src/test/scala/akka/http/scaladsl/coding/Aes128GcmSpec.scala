package akka.http.scaladsl.coding

import java.io.{FilterOutputStream, InputStream, OutputStream}
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64

import akka.http.impl.util._
import akka.stream.scaladsl.StreamConverters
import akka.testkit._
import akka.util.ByteString

import scala.concurrent.duration._

/**
 * Tests for the aes128gcm content encoding
 *
 * Note that the CoderSpec is designed to test encode/decode against a
 * reference implementation. However, no reference implementation is
 * readily available for aes128gcm, so we use our own implementation as
 * the reference for itself. As such, the tests in CoderSpec can only
 * validate that the implementation is internally consistent, not that
 * it is correct.
 *
 * To test correctness, the two test vectors are provided in RFC8188 are
 * checked here.
 */
class Aes128GcmSpec extends CoderSpec with GcmEncodingCryptoPrimitives {
  private val rand = new SecureRandom()
  private val encryptionKey = randByteArray(16)
  private val keyId = ""

  override def corruptInputCheck: Boolean = false  // TODO get this to check for authentication tag error instead of zip DataFormatException
  override protected def Coder: Coder with StreamDecoder = new Aes128GcmEncoding(
    _ => true,
    encryptionKey,
    keyId,
    _ => encryptionKey
  )

  override protected def newDecodedInputStream(underlying: InputStream): InputStream = {
    val decoder = new Aes128GcmDecoder(_ => encryptionKey)
    val source = StreamConverters.fromInputStream(() => underlying)
    val sink = StreamConverters.asInputStream()
    source.via(decoder).runWith(sink)
  }

  override protected def newEncodedOutputStream(underlying: OutputStream): OutputStream =
    new AesOutputStream(underlying, new Aes128GcmEncoder(encryptionKey, keyId))

  override def extraTests(): Unit = {

    "properly encode the test response body from the spec" in {
      val messageBytes = StandardCharsets.UTF_8.encode(Example1.message)
      Example1.encoder.compressAndFinish(ByteString(messageBytes)) shouldBe
        Example1.ciphertext
    }

    "properly decode the test response body from the spec" in {
      val decoded = Example1.decoder.decode(ByteString(Example1.ciphertext))
        .awaitResult(3.seconds.dilated)
        .asByteBuffer
      decoded shouldBe StandardCharsets.UTF_8.encode(Example1.message)
    }

    "properly decode the multi-record response from the spec" in {
      val decoded = Example2.decoder.decode(Example2.ciphertext)
        .awaitResult(3.seconds.dilated)
        .asByteBuffer
      decoded shouldBe StandardCharsets.UTF_8.encode(Example2.message)
    }

    "pad the current record on flush()" in {
      fail("Not implemented yet")
    }

    "Write the final record on finish()" in {
      fail("Not implemented yet")
    }

    "properly encode/decode with 32-bit record sizes" in {
      fail("Not implemented yet")
    }
  }

  private def randByteArray(len: Int): Array[Byte] = {
    val out = new Array[Byte](Aes128GcmEncoding.saltLength)
    rand.nextBytes(out)
    out
  }
}

/** Test Vector from RFC 8188 Section 3.1 */
object Example1 {
  val message = "I am the walrus"
  val key: Array[Byte] = Base64.getUrlDecoder.decode("yqdlZ-tYemfogSmv7Ws5PQ")
  val keyId = ""
  val recordSize = 4096
  val salt: Array[Byte] = List(0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d,
    0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b)
    .map(i => (i & 0xFF).toByte)
    .toArray
  val ciphertext: Array[Byte] = Base64.getUrlDecoder.decode(
    "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg"
  )
  val encoder = new Aes128GcmEncoder(
    key, keyId, recordSize, Some(salt))
  val decoder = new Aes128GcmEncoding(_ => true, key, "", _ => key)
}

/** Test Vector from RFC 8188 Section 3.2 */
object Example2 {
  val message = "I am the walrus"
  val key: Array[Byte] = Base64.getUrlDecoder.decode("BO3ZVPxUlnLORbVGMpbT1Q")
  val ciphertext = ByteString(Base64.getUrlDecoder.decode(
    "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA"
  ))
  val decoder = new Aes128GcmEncoding(_ => true, key, "", _ => key)
}

private class AesOutputStream(underlying: OutputStream, encoder: Aes128GcmEncoder)
  extends FilterOutputStream(underlying) {

  override def flush(): Unit = underlying.flush()

  override def write(b: Int): Unit = {
    val out = new Array[Byte](1)
    out(0) = (b & 0xff).toByte
    write(out)
  }

  override def write(b: Array[Byte]): Unit = write(b, 0, b.length)

  override def write(b: Array[Byte], off: Int, len: Int): Unit = underlying.write(
    encoder.compress(ByteString(b.slice(off, off + len))).toArray
  )

  override def close(): Unit = {
    underlying.write(encoder.finish().toArray)
    underlying.close()
  }
}
