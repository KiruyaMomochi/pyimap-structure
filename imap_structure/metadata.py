import collections.abc
import imaplib
import logging
import re
from dataclasses import dataclass
from email.message import Message
from typing import Optional, Sequence

from imap_structure.body_structure import BodyStructure, parse_body_structure
from imap_structure.parser import guess_encoding, parse_bytes

logger = logging.getLogger(__name__)


METADATA_MESSAGE_PARTS = (
    "(" + " ".join(["UID", "FLAGS", "BODYSTRUCTURE", "BODY[HEADER]"]) + ")"
)


@dataclass
class Metadata:
    flags: str
    encoding: str
    uid: int
    body_structure: BodyStructure
    header: Message


def fetch_raw_metadatas(
    mail: imaplib.IMAP4, message_set: str | int | Sequence[int] | Sequence[str]
) -> list:
    if isinstance(message_set, int) or isinstance(message_set, str):
        message_set = f"({message_set})"
    elif isinstance(message_set, collections.abc.Sequence):
        assert not isinstance(
            message_set, str
        )  # We don't want to get a string like "(1,2,3)"
        message_set_inner = ",".join(str(x) for x in message_set)
        message_set = f"({message_set_inner})"

    result, response = mail.fetch(message_set, METADATA_MESSAGE_PARTS)
    if result != "OK":
        logger.error(response)
        raise mail.error("Failed to fetch metadata")
    assert isinstance(response, list)
    return response


def fetch_raw_metadatas_uid(
    mail: imaplib.IMAP4, uid_set: str | int | Sequence[int] | Sequence[str]
) -> list:
    # UID should in the form of sequence-set, which is defined in RFC 9051
    # https://datatracker.ietf.org/doc/html/rfc9051#IMAP-ABNF
    if isinstance(uid_set, int) or isinstance(uid_set, str):
        uid_set = f"({uid_set})"
    elif isinstance(uid_set, collections.abc.Sequence):
        assert not isinstance(
            uid_set, str
        )  # We don't want to get a string like "(1,2,3)"
        if len(uid_set) == 0:
            return []
        message_set_inner = ",".join(str(x) for x in uid_set)
        uid_set = f"({message_set_inner})"

    result, response = mail.uid("fetch", uid_set, METADATA_MESSAGE_PARTS)
    if result != "OK":
        logger.error(response)
        raise mail.error("Failed to fetch metadata")
    assert isinstance(response, list)
    return response


def split_raw_metadatas(metadatas: list[tuple]) -> dict[int, list[bytes]]:
    result: dict[int, list[bytes]] = {}
    sequence: Optional[int] = None

    for item in metadatas:
        if item == b")":
            continue
        assert isinstance(item, tuple)
        item = list(item)
        assert isinstance(item[0], bytes)

        # re.match tries to match from the beginning of the string
        begin_match = re.match(rb"(\d+)\s+\((UID|FLAGS|BODYSTRUCTURE)", item[0])

        if begin_match is None:
            assert sequence is not None
            result[sequence] += item
        else:
            sequence = int(begin_match.group(1))
            result[sequence] = item
    return result


def parse_first_line(first_line: str):
    """
    Parse the line before the last of the metadata response.
    Which should contain FLAGS, UID and BODYSTRUCTURE.
    """

    # Instead of a detailed parser, we just use string magic for now.
    # It's silly...but works.

    # .*? is used to match as few characters as possible
    flags_match = re.search(r"\bFLAGS \((.*?)\)", first_line)
    assert flags_match is not None
    flags = flags_match.group(1)

    uid_match = re.search(r"\bUID (\d+)", first_line)
    assert uid_match is not None
    uid = int(uid_match.group(1))

    # NOTE: for parser to work correctly the parenthesis must be kept
    bodystructure_l_idx = (
        first_line.find(" BODYSTRUCTURE (") + len(" BODYSTRUCTURE (") - 1
    )
    bodystructure_r_idx = first_line.rfind(")") + 1
    bodystructure = first_line[bodystructure_l_idx:bodystructure_r_idx].strip()

    return (flags, uid, parse_body_structure(bodystructure))


def parse_metadata(metadata: Sequence[bytes]):
    header_bytes = metadata[-1]
    encoding = guess_encoding(header_bytes)
    header = parse_bytes(header_bytes, encoding=encoding)

    # The line before the last one will contain FLAGS, UID and BODYSTRUCTURE
    first_line = b"".join(metadata[0:-1]).decode(encoding=encoding)
    flags, uid, body_structure = parse_first_line(first_line)

    return Metadata(
        flags=flags,
        encoding=encoding,
        uid=uid,
        body_structure=body_structure,
        header=header,
    )


def fetch_metadatas(
    mail: imaplib.IMAP4, message_set: str | int | Sequence[int] | Sequence[str]
) -> dict[int, Metadata]:
    raw_metadatas = split_raw_metadatas(fetch_raw_metadatas(mail, message_set))
    metadatas = {i: parse_metadata(raw_metadatas[i]) for i in raw_metadatas}

    return metadatas


def fetch_metadatas_uid(
    mail: imaplib.IMAP4, uid_set: str | int | Sequence[int] | Sequence[str]
) -> dict[int, Metadata]:
    raw_metadatas = split_raw_metadatas(fetch_raw_metadatas_uid(mail, uid_set))
    metadatas = {i: parse_metadata(raw_metadatas[i]) for i in raw_metadatas}

    return metadatas
