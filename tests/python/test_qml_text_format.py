"""Every QML `Text` must set `textFormat`, and none may pick rich text.

Qt's default is `Text.AutoText`, which switches to `StyledText` whenever the
string looks like markup -- and Qt's own documentation says, of that mode:

    This functionality includes loading images remotely over the network.
    Thus, when displaying user-controlled, untrusted content, the textFormat
    should either be explicitly set to Text.PlainText, or the contents should
    be stripped of unwanted tags.

Every string tonearm renders is user-controlled in that sense: track titles,
album and artist names, zone names, the Core's own display name, browse rows
and breadcrumbs all arrive from the Roon Core. A track named
`<img src="http://203.0.113.9/x.png">` would make omarchy-shell -- the shared
process every widget lives in -- issue an HTTP request to an arbitrary host
when the popup renders. It does not take a hostile Core: an edited library
entry is enough, and a legitimate title containing `<` renders wrongly today.

Asserted across EVERY Text rather than only the ones known to carry Core
data, because that classification is a judgement someone has to make again on
every new binding, and the cost of being wrong is silent. `browse.strip_markup`
only rewrites Roon's own link syntax and `_clip` only bounds length; neither
touches HTML. See #22.
"""

import os
import re
import unittest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
QML = ("Panel.qml", "BrowsePane.qml")

# `Text {` but not `TextField {`, `TextInput {` or a property named *Text.
_TEXT_ITEM = re.compile(r"(?<![A-Za-z_.])Text\s*\{")


def text_blocks(source):
    """Every `Text { ... }` body, matched by brace depth."""
    for match in _TEXT_ITEM.finditer(source):
        depth, i = 0, match.end() - 1
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    yield match.start(), source[match.end():i]
                    break
            i += 1


class TestEveryTextDeclaresItsFormat(unittest.TestCase):
    def _source(self, name):
        with open(os.path.join(REPO, name)) as handle:
            return handle.read()

    def test_every_text_item_sets_textformat(self):
        missing = []
        for name in QML:
            source = self._source(name)
            for offset, body in text_blocks(source):
                if "textFormat" not in body:
                    line = source[:offset].count("\n") + 1
                    missing.append("%s:%d" % (name, line))
        self.assertEqual(missing, [], "Text items with no textFormat: %s" % missing)

    def test_no_text_item_opts_into_rich_text(self):
        # PlainText is the only safe choice here. StyledText and MarkdownText
        # are the modes that load remote images; AutoText is how you get them
        # by accident.
        bad = []
        for name in QML:
            source = self._source(name)
            for offset, body in text_blocks(source):
                fmt = re.search(r"textFormat\s*:\s*([A-Za-z.]+)", body)
                if fmt and fmt.group(1) != "Text.PlainText":
                    bad.append("%s:%d -> %s"
                               % (name, source[:offset].count("\n") + 1, fmt.group(1)))
        self.assertEqual(bad, [], "non-plain textFormat: %s" % bad)

    def test_the_scan_actually_finds_the_text_items(self):
        # A regex that matched nothing would make both tests above pass
        # vacuously, which is the failure mode that matters for a guard.
        total = sum(len(list(text_blocks(self._source(n)))) for n in QML)
        self.assertGreater(total, 15, "only found %d Text items" % total)
