from pathlib import Path

from nginxtrace.config.loader import load_file
from nginxtrace.config.models import Directive
from nginxtrace.config.parser import parse

def parse_file(file:Path) -> tuple[Directive, ...]:
    text = load_file(file)
    return parse(text, file)