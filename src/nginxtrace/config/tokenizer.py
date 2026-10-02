from dataclasses import dataclass

@dataclass(frozen=True)
class Token:
    value: str
    line: int

SPECIAL_CHARACTERS = {"{", "}", ";"}
QUOTE_CHARACTERS = {'"', "'"}

def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    line = 1

    while index < len(text):
        character = text[index]

        if character == "\n":
            line += 1
            index += 1
        elif character.isspace():
            index += 1
        elif character == "#":
            while index < len(text) and text[index] != "\n":
                index += 1
        elif character in SPECIAL_CHARACTERS:
            tokens.append(Token(character, line))
            index += 1
        elif character in QUOTE_CHARACTERS:
            token, index, line = read_quoted_token(text, index, line)
            tokens.append(token)
        else:
            token, index = read_unquoted_token(text, index, line)
            tokens.append(token)

    return tokens

def read_quoted_token(text: str, index: int, line: int) -> tuple[Token, int, int]:
    quote = text[index]
    start_line = line
    index += 1
    characters: list[str] = []

    while index < len(text):
        character = text[index]

        if character == "\\" and index + 1 < len(text):
            index += 1
            characters.append(text[index])
            index += 1
        elif character == quote:
            index += 1
            return Token("".join(characters), start_line), index, line
        else:
            if character == "\n":
                line += 1
            characters.append(character)
            index += 1

    raise ValueError(f"Unterminated quoted string starting on line {start_line}")

def read_unquoted_token(text: str, index: int, line: int) -> tuple[Token, int]:
    start = index
    while (
        index < len(text)
        and not text[index].isspace()
        and text[index] not in SPECIAL_CHARACTERS
        and text[index] not in QUOTE_CHARACTERS
    ):
        index += 1

    return Token(text[start:index], line), index