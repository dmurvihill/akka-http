/*
 * Copyright (C) 2015-2019 Lightbend Inc. <https://www.lightbend.com>
 */

package akka.http.scaladsl.coding.newbytestringparser

import akka.annotation.InternalApi
import akka.stream._
import akka.stream.stage._
import akka.util.ByteString

import scala.annotation.tailrec
import scala.util.control.{NoStackTrace, NonFatal}

/**
  * INTERNAL API
  */
//noinspection ScalaFileName
@InternalApi private[akka] abstract class ByteStringParser[T] extends GraphStage[FlowShape[ByteString, T]] {
  import ByteStringParser._

  private val bytesIn = Inlet[ByteString]("bytesIn")
  private val objOut = Outlet[T]("objOut")

  override def initialAttributes: Attributes = Attributes.name("ByteStringParser")
  final override val shape = FlowShape(bytesIn, objOut)

  class ParsingLogic extends GraphStageLogic(shape) with InHandler with OutHandler {
    private var inBuffer = ByteString.empty
    private var outBuffer: Stream[T] = Stream.empty
    private var current: ParseStep[T] = FinishedParser
    private var acceptUpstreamFinish: Boolean = true
    private var untilCompact = CompactionThreshold

    final protected def startWith(step: ParseStep[T]): Unit = current = step

    protected def recursionLimit: Int = 1000

    /**
     * doParse() is the main driver for the parser. It can be called from onPush, onPull and onUpstreamFinish.
     * The general logic is that invocation of this method either results in an emitted parsed element, or an indication
     * that there is more data needed.
     *
     * On completion there are various cases:
     *  - input buffer is empty: parser accepts completion or fails.
     *  - input buffer is non-empty, we wait for a pull. This might result in a few more onPull-push cycles, served from the
     *    buffer. This can lead to two conditions:
     *     - drained, empty input buffer. This is either accepted completion (acceptUpstreamFinish) or a truncation.
     *     - parser demands more data than in buffer. This is always a truncation.
     *
     * If the return value is true the method must be called another time to continue processing.
     */
    private def doParseInner(): Boolean =
      if (inBuffer.nonEmpty) {
        val reader = new ByteReader(inBuffer)
        try {
          val parseResult = current.parse(reader)
          acceptUpstreamFinish = parseResult.acceptUpstreamFinish
          outBuffer ++= parseResult.result
          current = parseResult.nextStep

          if (parseResult.nextStep == FinishedParser) {
            DontRecurse
          } else {
            inBuffer = reader.remainingData

            // If this step didn't produce a result, continue parsing.
            if (parseResult.result.isEmpty)
              Recurse
            else
              DontRecurse
          }
        } catch {
          case NeedMoreData =>
            acceptUpstreamFinish = false
            if (current.canWorkWithPartialData) inBuffer = reader.remainingData

            // Not enough data in buffer and upstream is closed
            if (isClosed(bytesIn)) truncated()
            else pull(bytesIn)

            DontRecurse
          case NonFatal(ex) =>
            failStage(new ParsingException(s"Parsing failed in step $current", ex))

            DontRecurse
        }
      } else {
        if (isClosed(bytesIn)) {
          // Buffer is empty and upstream is done. If the current phase accepts completion we are done,
          // otherwise report truncation.
          if (acceptUpstreamFinish) current = FinishedParser
          else truncated()
        } else pull(bytesIn)

        DontRecurse
      }

    private def truncated(): Unit = {
      outBuffer ++= current.onTruncation(inBuffer)
      current = FinishedParser
    }

    @tailrec private def doParse(remainingRecursions: Int = recursionLimit): Unit =
      if (remainingRecursions == 0)
        failStage(
          new IllegalStateException(
            s"Parsing logic didn't produce result after $recursionLimit steps. " +
              "Aborting processing to avoid infinite cycles. In the unlikely case that the parsing logic " +
              "needs more recursion, override ParsingLogic.recursionLimit."))
      else {
        val recurse = doParseInner()
        if (recurse) doParse(remainingRecursions - 1)
      }

    private def nextStep(): Unit = {
      if (outBuffer.nonEmpty) push()
      else {
        doParse()
        if (outBuffer.nonEmpty) push()
      }
      if (outBuffer.isEmpty && current == FinishedParser) {
        completeStage()
      }
    }

    private def push(): Unit = {
      push(objOut, outBuffer.head)
      outBuffer = outBuffer.tail
    }

    // Completion is handled by nextStep as the input buffer either gets empty after this call, or the parser requests
    // data that we can no longer provide (truncation).
    override def onPull(): Unit = nextStep()

    def onPush(): Unit = {
      // Buffer management before we call nextStep():
      //  - append new bytes
      //  - compact input buffer if necessary
      inBuffer ++= grab(bytesIn)
      untilCompact -= 1
      if (untilCompact == 0) {
        // Compaction prevents of ever growing tree (list) of ByteString if buffer contents overlap most of the
        // time and hence keep referring to old buffer ByteStrings. Compaction is performed only once in a while
        // to reduce cost of copy.
        untilCompact = CompactionThreshold
        inBuffer = inBuffer.compact
      }
      nextStep()
    }

    override def onUpstreamFinish(): Unit = {
      // If we have no a pending pull from downstream, attempt to invoke the parser again. This will handle
      // truncation if necessary, or complete the stage (and maybe a final emit).
      if (isAvailable(objOut)) nextStep()
      // if we do not have a pending pull,
      else if (inBuffer.isEmpty) {
        if (acceptUpstreamFinish) current = FinishedParser
        else truncated()
      }
    }

    setHandlers(bytesIn, objOut, this)
  }
}

/**
  * INTERNAL API
  */
//noinspection ScalaFileName
@InternalApi private[akka] object ByteStringParser {

  val CompactionThreshold = 16

  private final val Recurse = true
  private final val DontRecurse = false

  /**
    * @param result - parser can return some element for downstream or return None if no element was generated in this step
    *               and parsing should immediately continue with the next step.
    * @param nextStep - next parser
    * @param acceptUpstreamFinish - if true - stream will complete when received `onUpstreamFinish`, if "false"
    *                             - onTruncation will be called
    */
  case class ParseResult[+T](result: Traversable[T], nextStep: ParseStep[T], acceptUpstreamFinish: Boolean = true)

  trait ParseStep[+T] {

    /**
      * Must return true when NeedMoreData will clean buffer. If returns false - next pulled
      * data will be appended to existing data in buffer
      */
    def canWorkWithPartialData: Boolean = false
    def parse(reader: ByteReader): ParseResult[T]

    /** Recover when the parser expects more data than is available.
     *
     * If this method returns, the parser will continue to emit the
     * return values and then stop normally.
     * */
    def onTruncation(remaining: ByteString): Traversable[T] =
      throw new IllegalStateException("truncated data in ByteStringParser")
  }

  object FinishedParser extends ParseStep[Nothing] {
    override def parse(reader: ByteReader) =
      throw new IllegalStateException("no initial parser installed: you must use startWith(...)")
  }

  class ParsingException(msg: String, cause: Throwable) extends RuntimeException(msg, cause)

  val NeedMoreData = new Exception with NoStackTrace

  class ByteReader(input: ByteString) {

    private[this] var off = 0

    def hasRemaining: Boolean = off < input.size
    def remainingSize: Int = input.size - off

    def currentOffset: Int = off

    def remainingData: ByteString = input.drop(off)
    def fromStartToHere: ByteString = input.take(off)

    def take(n: Int): ByteString =
      if (off + n <= input.length) {
        val o = off
        off = o + n
        input.slice(o, off)
      } else throw NeedMoreData
    def takeAll(): ByteString = {
      val ret = remainingData
      off = input.size
      ret
    }

    def readByte(): Int =
      if (off < input.length) {
        val x = input(off)
        off += 1
        x & 0xFF
      } else throw NeedMoreData
    def readShortLE(): Int = readByte() | (readByte() << 8)
    def readIntLE(): Int = readShortLE() | (readShortLE() << 16)
    def readLongLE(): Long = (readIntLE() & 0XFFFFFFFFL) | ((readIntLE() & 0XFFFFFFFFL) << 32)

    def readShortBE(): Int = (readByte() << 8) | readByte()
    def readIntBE(): Int = (readShortBE() << 16) | readShortBE()
    def readLongBE(): Long = ((readIntBE() & 0XFFFFFFFFL) << 32) | (readIntBE() & 0XFFFFFFFFL)

    def skip(numBytes: Int): Unit =
      if (off + numBytes <= input.length) off += numBytes
      else throw NeedMoreData
    def skipZeroTerminatedString(): Unit = while (readByte() != 0) {}
  }
}
