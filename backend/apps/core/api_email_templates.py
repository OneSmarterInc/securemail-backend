"""Restricted notification markup: no URLs, scripts, images or executable templates."""

import html
import re
from html.parser import HTMLParser

TAGS = {
    "p",
    "div",
    "span",
    "h1",
    "h2",
    "h3",
    "strong",
    "em",
    "b",
    "i",
    "br",
    "hr",
    "ul",
    "ol",
    "li",
    "table",
    "tbody",
    "tr",
    "td",
    "th",
}
COLORS = {"color", "background-color", "border-color"}
LENGTHS = {
    "font-size",
    "padding",
    "padding-top",
    "padding-bottom",
    "padding-left",
    "padding-right",
    "margin",
    "margin-top",
    "margin-bottom",
    "border-radius",
    "border-width",
}
CHOICES = {
    "text-align": {"left", "center", "right"},
    "font-weight": {"normal", "bold", "400", "500", "600", "700"},
    "font-family": {"Arial", "Verdana", "Georgia", "sans-serif", "serif"},
    "border-style": {"solid", "none"},
    "border-collapse": {"collapse", "separate"},
}


def safe_css(value: str) -> str:
    if len(value) > 2000:
        raise ValueError("CSS is too long.")
    result = []
    for declaration in value.split(";"):
        if not declaration.strip():
            continue
        name, separator, content = declaration.partition(":")
        name, content = name.strip().lower(), content.strip()
        valid = False
        if name in COLORS:
            valid = bool(re.fullmatch(r"#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?", content))
        elif name in LENGTHS:
            valid = bool(re.fullmatch(r"(?:0|[1-9][0-9]?)px", content))
        elif name in CHOICES:
            valid = content in CHOICES[name]
        if not separator or not valid:
            raise ValueError("Unsupported CSS property or value.")
        result.append(f"{name}:{content}")
    return ";".join(result)


class NotificationMarkup(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.output = []
        self.stack = []

    def handle_starttag(self, tag, attrs):
        if tag not in TAGS or len(self.stack) >= 20:
            raise ValueError("Unsupported HTML tag or nesting depth.")
        rendered = []
        seen = set()
        for name, value in attrs:
            if name != "style" or name in seen or value is None:
                raise ValueError("Only inline style attributes are supported.")
            seen.add(name)
            rendered.append(f' style="{html.escape(safe_css(value), quote=True)}"')
        self.output.append(f"<{tag}{''.join(rendered)}>")
        if tag not in {"br", "hr"}:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack.pop() != tag:
            raise ValueError("HTML tags must be balanced.")
        self.output.append(f"</{tag}>")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in {"br", "hr"}:
            self.handle_endtag(tag)

    def handle_data(self, data):
        self.output.append(html.escape(data))

    def handle_comment(self, data):
        raise ValueError("HTML comments are not supported.")

    def handle_decl(self, decl):
        raise ValueError("HTML declarations are not supported.")

    def handle_pi(self, data):
        raise ValueError("Processing instructions are not supported.")

    def unknown_decl(self, data):
        raise ValueError("HTML declarations are not supported.")


def validate_markup(markup: str, css: str) -> str:
    parser = NotificationMarkup()
    parser.feed(markup)
    parser.close()
    if parser.stack:
        raise ValueError("HTML tags must be balanced.")
    return f'<div style="{html.escape(safe_css(css), quote=True)}">{"".join(parser.output)}</div>'


def render_notification(template: dict, link: str) -> str:
    content = validate_markup(template["html"], template.get("css", ""))
    header, primary = brand_header(template)
    # The application, never caller HTML, controls the verification destination.
    return (
        '<!doctype html><html><body><div style="max-width:600px;margin:auto;padding:20px">'
        + header
        + content
        + f'<p><a style="background-color:{primary};color:#ffffff;padding:12px;display:inline-block" href="'
        + html.escape(link, quote=True)
        + '">Read secure message</a></p><p>Verify your email to read the protected message. '
        "This notification was sent through OneSmarter Secure Mail.</p></div></body></html>"
    )


def render_otp(template: dict, code: str) -> str:
    if not re.fullmatch(r"\d{6}", code):
        raise ValueError("Invalid verification code.")
    content = validate_markup(template["otp_html"], template.get("otp_css", ""))
    header, primary = brand_header(template)
    return (
        '<!doctype html><html><body><div style="max-width:600px;margin:auto;padding:20px">'
        + header
        + content
        + f'<p style="color:{primary};font-size:32px;font-weight:bold;letter-spacing:6px">'
        + code
        + "</p><p>This code expires in 10 minutes. Do not share it. Enter it only in "
        "OneSmarter Secure Mail. If you did not request it, ignore this email.</p>"
        "<p>Verification provided by OneSmarter Secure Mail.</p></div></body></html>"
    )


def brand_header(template):
    from .api_presentation import validate_theme

    if not template.get("theme"):
        return "", "#117c78"
    theme = validate_theme(template["theme"])
    return f'<p style="font-size:22px;font-weight:bold">{html.escape(theme["name"])}</p>', theme[
        "primary"
    ]
