"""A scripted fake of the Anthropic Messages API, for exercising the real Claude Code CLI offline.

Serves POST /v1/messages. Each request advances a scripted turn; supports both the plain JSON
response and the SSE streaming form (when the request body sets "stream": true). Logs every
request body to REQ_LOG so the shape the CLI sends can be inspected.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

WORKSPACE = os.environ["FAKE_WS"]
REQ_LOG = os.environ.get("FAKE_REQ_LOG")

TURNS = [
    [{"type": "tool_use", "id": "toolu_01", "name": "Skill", "input": {"skill": "demo-skill"}}],
    [
        {
            "type": "tool_use",
            "id": "toolu_02",
            "name": "Read",
            "input": {"file_path": f"{WORKSPACE}/README.md"},
        }
    ],
    [
        {
            "type": "tool_use",
            "id": "toolu_03",
            "name": "Write",
            "input": {"file_path": f"{WORKSPACE}/notes.md", "content": "# notes\nhello\n"},
        }
    ],
    [{"type": "text", "text": "Read README.md and wrote notes.md."}],
]
STATE = {"turn": 0}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length)
        if REQ_LOG:
            with Path(REQ_LOG).open("ab") as log:
                log.write(
                    json.dumps({"path": self.path, "headers": dict(self.headers)}).encode() + b"\n"
                )
                log.write(body + b"\n")
        try:
            request = json.loads(body)
        except ValueError:
            request = {}
        if not self.path.split("?")[0].endswith("/messages"):
            self.send_response(404)
            self.end_headers()
            return
        index = min(STATE["turn"], len(TURNS) - 1)
        STATE["turn"] += 1
        content = TURNS[index]
        stop = "tool_use" if content[0]["type"] == "tool_use" else "end_turn"
        message = {
            "id": f"msg_{index + 1:03d}",
            "type": "message",
            "role": "assistant",
            "model": "fake-model-v1",
            "content": content,
            "stop_reason": stop,
            "stop_sequence": None,
            "usage": {"input_tokens": 100 + index, "output_tokens": 20 + index},
        }
        if request.get("stream"):
            self._stream(message)
        else:
            payload = json.dumps(message).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    def _stream(self, message):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.end_headers()

        def event(name, data):
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()

        start = dict(message)
        start["content"] = []
        start["stop_reason"] = None
        start["usage"] = {"input_tokens": message["usage"]["input_tokens"], "output_tokens": 1}
        event("message_start", {"type": "message_start", "message": start})
        for index, block in enumerate(message["content"]):
            if block["type"] == "text":
                event(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {"type": "text", "text": ""},
                    },
                )
                event(
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "text_delta", "text": block["text"]},
                    },
                )
            else:
                event(
                    "content_block_start",
                    {
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": block["id"],
                            "name": block["name"],
                            "input": {},
                        },
                    },
                )
                event(
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": json.dumps(block["input"]),
                        },
                    },
                )
            event("content_block_stop", {"type": "content_block_stop", "index": index})
        event(
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
                "usage": {"output_tokens": message["usage"]["output_tokens"]},
            },
        )
        event("message_stop", {"type": "message_stop"})


if __name__ == "__main__":
    port = int(sys.argv[1])
    host = sys.argv[2] if len(sys.argv) > 2 else "127.0.0.1"
    HTTPServer((host, port), Handler).serve_forever()
