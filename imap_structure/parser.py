from email import policy
from email.message import Message
from email.parser import BytesParser, Parser

bytes_parser = BytesParser(policy=policy.default)
parser = Parser(policy=policy.default)


def guess_encoding(text: bytes) -> str:
    """
    Guess encoding of message header
    Currently, it just read charset parameter from Content-Type header,
    if the parameter is not fond, we will use ASCII.

    :param text: bytes of message header, possibly with body
    """

    # Parse header
    parsed_header = bytes_parser.parsebytes(text, headersonly=True)
    # Get encoding from header
    encoding = parsed_header.get_content_charset()

    if encoding is None:
        # FIXME: We should guess here
        encoding = "ASCII"
    return encoding


def parse_string(text: str) -> Message:
    parsed = parser.parsestr(text)
    return parsed


def parse_bytes(text: bytes, encoding: str | None = None) -> Message:
    """
    Decode message bytes into EmailMessage
    """

    # If you see the source code of BytesParser, you will find that it just
    # decode it to ASCII. Therefore, we try to guess the encoding here.

    if encoding is None:
        encoding = guess_encoding(text)
    decoded = text.decode(encoding, errors="surrogateescape")
    parsed = parser.parsestr(decoded)  # type: ignore

    return parsed


def parse_section(header: str, body: bytes):
    message = parser.parsestr(header)
    message.set_payload(body)
    return message
