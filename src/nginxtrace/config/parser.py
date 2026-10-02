from pathlib import Path

from nginxtrace.config.models import Directive
from nginxtrace.config.tokenizer import Token, tokenize

class ParseError(ValueError):
    """Raised when parsing of NGINX syntax configuration fails"""

class Parser:
    def __init__(self, tokens: list[Token], file: Path) -> None:
        self.tokens = tokens
        self.file = file
        self.index = 0

    def parse(self) -> tuple[Directive, ...]:
        directives = self.parse_directives()

        if self.current_token() is not None:
            token = self.current_token()
            raise ParseError(
                f"Unexpected token {token.value!r} on line {token.line}"
            )
        return directives

    def parse_directives(self) -> tuple[Directive, ...]:
        directives: list[Directive] = []

        while self.current_token() is not None and self.current_token().value != "}":
            directives.append(self.parse_directive())

        return tuple(directives)

    def parse_directive(self) -> Directive:
        name_token = self.require_token("Expected a directive name")
        name = name_token.value
        self.advance()
        arguments: list[str] = []

        while True:
            token = self.require_token(
                f"Expected ';' or '{{' after directive {name!r}"
            )

            if token.value == ";":
                self.advance()
                return  Directive(
                    name=name,
                    arguments=tuple(arguments),
                    file=self.file,
                    line=name_token.line,
                )

            if token.value == "{":
                self.advance()
                children = self.parse_directives()
                closing_token = self.require_token(
                    f"Expected '}}' to close directive {name!r}"
                )

                if closing_token.value != "}":
                    raise ParseError(
                        f"Expected '}}' to close directive {name!r} "
                        f"on line {closing_token.line} "
                    )

                self.advance()
                return Directive(
                    name=name,
                    arguments=tuple(arguments),
                    file=self.file,
                    line=name_token.line,
                    children=children,
                )

            if token.value == "}":
                raise ParseError(
                    f"Unexpected '}}' after directive {name!r} on line {token.line}"
                )

            arguments.append(token.value)
            self.advance()

    def current_token(self) -> Token | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def advance(self) -> None:
        self.index += 1

    def require_token(self, message: str) -> Token:
        token = self.current_token()

        if token is None:
            raise ParseError(message)

        return token

def parse(text:str, file: Path) -> tuple[Directive, ...]:
    try:
        tokens = tokenize(text)
    except ValueError as err:
        raise ParseError(str(err)) from err

    parser = Parser(tokens, file)
    return parser.parse()