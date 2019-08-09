package akka.http.scaladsl.coding

import scala.concurrent.duration._
import java.io.{FilterOutputStream, InputStream, OutputStream}
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import akka.http.impl.util._
import akka.testkit._

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
 * To test correctness, the two test vectors are provided in RFC8188 are
 * checked here.
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

    /* RFC 8188 Section 3.1 */
    "properly encode the test response body from the spec" in {
      val message = ByteString(StandardCharsets.UTF_8.encode("I am the walrus"))
      val key = Base64.getUrlDecoder.decode("yqdlZ-tYemfogSmv7Ws5PQ")
      val keyId = ""
      val salt: Array[Byte] = List(0x23, 0x50, 0x6c, 0xc6, 0xd1, 0x6d,
        0xb6, 0x5b, 0xf7, 0xbb, 0xf3, 0xa8, 0xf7, 0x8c, 0x67, 0x9b)
        .map(i => (i & 0xFF).toByte)
        .toArray
      val compressor = new Aes128GcmEncoder(key, keyId, 4096, Some(salt))
      val expectedOutput = Base64.getUrlDecoder.decode(
        "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg"
      )
      val output = compressor.compressAndFinish(message)
      output shouldBe expectedOutput
    }

    "properly decode the test response body from the spec" in {
      val key = Base64.getUrlDecoder.decode("yqdlZ-tYemfogSmv7Ws5PQ")
      val decoder = new Aes128GcmEncoding(_ => true, key, "", _ => key)
      val ciphertext = ByteString(Base64.getUrlDecoder.decode(
        "I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg"
      ))
      val decoded = decoder.decode(ciphertext)
        .awaitResult(3.seconds.dilated)
        .asByteBuffer
      decoded shouldBe StandardCharsets.UTF_8.encode("I am the walrus")
    }

    "properly decode the multi-record response from the spec" in {
      val key = Base64.getUrlDecoder.decode("BO3ZVPxUlnLORbVGMpbT1Q")
      val decoder = new Aes128GcmEncoding(_ => true, key, "", _ => key)
      val ciphertext = ByteString(Base64.getUrlDecoder.decode(
        "uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA"
      ))
      val decoded = decoder.decode(ciphertext)
        .awaitResult(3.seconds.dilated)
        .asByteBuffer
      decoded shouldBe StandardCharsets.UTF_8.encode("I am the walrus")
    }

    "pad the current record on flush()" in {
      fail("Not implemented yet")
    }

    "Write the final record on finish()" in {
      fail("Not implemented yet")
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
