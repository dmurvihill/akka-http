package akka.http.scaladsl.coding

import java.io.{ FilterOutputStream, InputStream, OutputStream }
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64

import akka.stream.scaladsl.StreamConverters
import akka.util.ByteString

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
 * The two test vectors are provided in RFC8188 are tested here. (TODO)
 */
class Aes128GcmSpec extends CoderSpec with GcmEncodingCryptoPrimitives {
  private val rand = new SecureRandom()
  private val encryptionKey = randByteArray(16)
  private val keyId = ""

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
    "correctly encode the example in RFC 8188 section 3.1" in {
      val key = Base64.getUrlDecoder.decode("yqdlZ-tYemfogSmv7Ws5PQ")
      new Aes128GcmEncoding(
        _ => true,
        key,
        "",
        _ => key
      ).encode(ByteString(StandardCharsets.UTF_8.encode("I am the walrus")))
    }
  }

  private def randByteArray(len: Int): Array[Byte] = {
    val out = new Array[Byte](Aes128GcmEncoding.saltLength)
    rand.nextBytes(out)
    out
  }
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
    encoder.finish()
    underlying.close()
  }
}
