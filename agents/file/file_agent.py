import os
import re

# Phase 31 — MarkItDown lazy import (heavy deps, only load when needed)
_markitdown = None

def _get_md():
    global _markitdown
    if _markitdown is None:
        from markitdown import MarkItDown
        _markitdown = MarkItDown()
    return _markitdown

# Friendly, spoken names per file type — so we say "your PDF", not "4567353982-423.pdf"
_TYPE_WORDS = {
    ".pdf": "PDF", ".docx": "Word document", ".doc": "Word document",
    ".pptx": "presentation", ".ppt": "presentation",
    ".xlsx": "spreadsheet", ".xls": "spreadsheet", ".csv": "spreadsheet",
    ".png": "image", ".jpg": "image", ".jpeg": "image", ".gif": "image",
    ".bmp": "image", ".webp": "image",
    ".mp3": "audio file", ".wav": "audio file", ".m4a": "audio file",
    ".txt": "text file", ".md": "note", ".html": "web page", ".htm": "web page",
    ".json": "file", ".xml": "file", ".zip": "archive",
}


def _friendly_name(path: str) -> str:
    """Speak a clean name. Hash/number-blob filenames -> generic 'that <type>'."""
    base = os.path.basename(path or "")
    stem, ext = os.path.splitext(base)
    word = _TYPE_WORDS.get(ext.lower(), "file")
    # ugly stem = mostly digits/hex/separators (e.g. 4567353982-423) -> hide it
    letters = re.sub(r"[^A-Za-z]", "", stem)
    if len(stem) >= 6 and len(letters) <= max(2, len(stem) // 4):
        return f"that {word}"
    # human-ish name -> say "the <name> <type>"
    nice = stem.replace("_", " ").replace("-", " ").strip()
    return f'the "{nice}" {word}' if nice else f"that {word}"


# Supported extensions for read_document
_READABLE_EXTS = {
    ".pdf", ".docx", ".doc", ".pptx", ".ppt",
    ".xlsx", ".xls", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",  # OCR
    ".mp3", ".wav", ".m4a",                             # audio transcription
    ".txt", ".md", ".html", ".htm", ".xml", ".json",
    ".zip",
}


class FileAgent:
    """
    Standardized File Agent

    Purpose:
    - Create files
    - Delete files
    - List files
    - Open files/folders

    Standard agent interface:
    run(input_text, action, parameters)

    Returns:
    {
        "success": bool,
        "message": str,
        "data": dict
    }
    """

    # =====================================
    # CREATE FILE
    # =====================================
    def create_file(
        self,
        path: str
    ):

        if not path:

            return {
                "success": False,
                "message":
                "File path missing.",
                "data": {}
            }

        try:

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as f:

                f.write("")

            return {

                "success": True,

                "message":
                f"File created: {path}",

                "data": {
                    "path": path
                }
            }

        except Exception as e:

            return {

                "success": False,

                "message":
                f"Failed to create file: "
                f"{str(e)}",

                "data": {}
            }

    # =====================================
    # DELETE FILE
    # =====================================
    def delete_file(
        self,
        path: str
    ):

        if not path:

            return {
                "success": False,
                "message":
                "File path missing.",
                "data": {}
            }

        if not os.path.exists(
            path
        ):

            return {

                "success": False,

                "message":
                "File not found.",

                "data": {
                    "path":
                    path
                }
            }

        if os.path.isdir(
            path
        ):

            return {

                "success": False,

                "message":
                "Cannot delete folders.",

                "data": {
                    "path":
                    path
                }
            }

        try:

            os.remove(path)

            return {

                "success": True,

                "message":
                f"Deleted file: "
                f"{path}",

                "data": {
                    "path":
                    path
                }
            }

        except Exception as e:

            return {

                "success": False,

                "message":
                f"Failed to delete "
                f"file: {str(e)}",

                "data": {}
            }

    # =====================================
    # LIST FILES
    # =====================================
    def list_files(
        self,
        path="."
    ):

        if not os.path.exists(
            path
        ):

            return {

                "success": False,

                "message":
                "Path does not exist.",

                "data": {
                    "path":
                    path
                }
            }

        try:

            files = os.listdir(
                path
            )

            preview = (
                files[:10]
            )

            more_count = (
                len(files)
                - len(preview)
            )

            message = (
                "No files found."
            )

            if files:

                message = (
                    "Files:\n"
                    + "\n".join(
                        preview
                    )
                )

                if more_count > 0:

                    message += (
                        f"\n...and "
                        f"{more_count} "
                        f"more files"
                    )

            return {

                "success": True,

                "message":
                message,

                "data": {

                    "path":
                    path,

                    "files":
                    files
                }
            }

        except Exception as e:

            return {

                "success": False,

                "message":
                f"Failed to list "
                f"files: {str(e)}",

                "data": {}
            }

    # =====================================
    # OPEN FILE / FOLDER
    # =====================================
    def open_file(
        self,
        path: str
    ):

        if not path:

            return {

                "success": False,

                "message":
                "File path missing.",

                "data": {}
            }

        if not os.path.exists(
            path
        ):

            return {

                "success": False,

                "message":
                "File not found.",

                "data": {
                    "path":
                    path
                }
            }

        try:

            os.startfile(path)

            return {

                "success": True,

                "message":
                f"Opening {_friendly_name(path)} for you.",

                "data": {
                    "path":
                    path
                }
            }

        except Exception as e:

            return {

                "success": False,

                "message":
                f"Failed to open file: "
                f"{str(e)}",

                "data": {}
            }

    # =====================================
    # READ DOCUMENT (Phase 31 — MarkItDown)
    # =====================================
    def read_document(self, path: str, max_chars: int = 8000) -> dict:
        """
        Convert any document to Markdown text using MarkItDown.
        Supports: PDF, DOCX, PPTX, XLSX, CSV, PNG/JPG (OCR), MP3 (transcription),
                  TXT, HTML, ZIP, and more.
        """
        if not path:
            return {"success": False, "message": "File path missing.", "data": {}}

        # URL input → SSRF guard with redirect re-validation (W3). We fetch via
        # safe_get (validates every hop) then hand the bytes to MarkItDown, so the
        # library never follows a redirect to an internal host behind our back.
        if re.match(r"https?://", path, re.IGNORECASE):
            from core.url_guard import safe_get
            import tempfile as _tf
            try:
                resp = safe_get(path)
            except ValueError as e:
                return {"success": False, "message": f"Refused to fetch URL — {e}.", "data": {}}
            except Exception as e:
                return {"success": False, "message": f"Failed to fetch URL: {e}", "data": {}}
            try:
                from urllib.parse import urlsplit as _usplit
                ext = os.path.splitext(_usplit(path).path)[1] or ".html"
                with _tf.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
                    tmp.write(resp.content)
                    tmp_path = tmp.name
                try:
                    md = _get_md()
                    result = md.convert(tmp_path)
                    text = (result.text_content or "")[:max_chars]
                finally:
                    try: os.remove(tmp_path)
                    except Exception: pass
                if not text.strip():
                    return {"success": False, "message": "No text extracted from URL.", "data": {}}
                return {"success": True, "message": text,
                        "data": {"url": path, "chars": len(text)}}
            except Exception as e:
                return {"success": False, "message": f"Failed to read URL content: {e}", "data": {}}

        # Expand ~
        path = os.path.expanduser(path)

        if not os.path.exists(path):
            return {"success": False, "message": "I couldn't find that file, boss.", "data": {}}

        ext = os.path.splitext(path)[1].lower()
        if ext not in _READABLE_EXTS:
            return {
                "success": False,
                "message": "I can't read that kind of file, boss.",
                "data": {}
            }

        try:
            md = _get_md()
            result = md.convert(path)
            text = result.text_content or ""

            if not text.strip():
                return {"success": False, "message": f"There's no readable text in {_friendly_name(path)}.", "data": {}}

            # Truncate if too long (LLM context limit)
            truncated = len(text) > max_chars
            text_out = text[:max_chars] + ("\n\n[...truncated]" if truncated else "")

            return {
                "success": True,
                "message": text_out,
                "data": {
                    "path": path,
                    "filename": os.path.basename(path),
                    "ext": ext,
                    "chars": len(text),
                    "truncated": truncated,
                }
            }
        except Exception as e:
            print(f"[file] read error for {path}: {e}")
            return {"success": False, "message": f"I had trouble reading {_friendly_name(path)}, boss.", "data": {}}

    def summarize_document(self, path: str) -> dict:
        """
        Read document then ask LLM to summarize it.
        Returns LLM summary as message (ready for TTS).
        """
        read_result = self.read_document(path, max_chars=6000)
        if not read_result["success"]:
            return read_result

        content = read_result["message"]
        filename = read_result["data"].get("filename", os.path.basename(path))

        try:
            import requests as _req
            from config import OLLAMA_MODEL, OLLAMA_HOST
            prompt = (
                f"Summarize this document in plain spoken English. "
                f"No bullet points or markdown. Just 3-5 clear sentences.\n\n"
                f"Document: {filename}\n\n"
                f"{content[:4000]}"
            )
            r = _req.post(
                f"{OLLAMA_HOST}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
                      "temperature": 0.3, "num_predict": 300},
                timeout=60,
            )
            summary = r.json().get("response", "").strip()
            if not summary:
                # Fallback: return first 500 chars of raw content
                summary = content[:500]

            return {
                "success": True,
                "message": summary,
                "data": read_result["data"]
            }
        except Exception as e:
            # If LLM fails, return raw text snippet
            return {
                "success": True,
                "message": content[:500],
                "data": read_result["data"]
            }

    # =====================================
    # APPLY PATCH (Phase 40d — unified diff)
    # =====================================
    def apply_patch(self, path: str, diff_text: str) -> dict:
        """Apply a unified diff to a file. Verifies context before writing;
        aborts atomically if any hunk doesn't match (no partial writes)."""
        if not path or not diff_text:
            return {"success": False, "message": "Need both a file path and diff text.", "data": {}}

        path = os.path.expanduser(path)
        if not os.path.exists(path):
            return {"success": False, "message": f"File not found: {path}", "data": {}}

        try:
            with open(path, "r", encoding="utf-8") as f:
                orig = f.read().splitlines(keepends=False)
        except Exception as e:
            return {"success": False, "message": f"Couldn't read file: {e}", "data": {}}

        # Parse hunks: @@ -s,c +s,c @@
        hunks = []
        cur = None
        for line in diff_text.splitlines():
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if m:
                if cur:
                    hunks.append(cur)
                cur = {"src_start": int(m.group(1)), "lines": []}
            elif cur is not None:
                if line and line[0] in (" ", "+", "-"):
                    cur["lines"].append(line)
                elif line.startswith("---") or line.startswith("+++") or line.startswith("diff "):
                    continue
        if cur:
            hunks.append(cur)

        if not hunks:
            return {"success": False, "message": "No valid unified-diff hunks found.", "data": {}}

        # Apply hunks → build new content, verifying context/removed lines
        result = list(orig)
        offset = 0
        added = removed = 0
        for h in hunks:
            idx = h["src_start"] - 1 + offset   # 0-based position in result
            cursor = idx
            for dl in h["lines"]:
                tag, content = dl[0], dl[1:]
                if tag == " ":
                    if cursor >= len(result) or result[cursor] != content:
                        return {"success": False,
                                "message": f"Patch context mismatch at line {cursor+1}. Aborted, file unchanged.",
                                "data": {}}
                    cursor += 1
                elif tag == "-":
                    if cursor >= len(result) or result[cursor] != content:
                        return {"success": False,
                                "message": f"Patch removal mismatch at line {cursor+1}. Aborted, file unchanged.",
                                "data": {}}
                    del result[cursor]
                    offset -= 1
                    removed += 1
                elif tag == "+":
                    result.insert(cursor, content)
                    cursor += 1
                    offset += 1
                    added += 1

        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(result) + ("\n" if orig or result else ""))
        except Exception as e:
            return {"success": False, "message": f"Write failed: {e}", "data": {}}

        return {
            "success": True,
            "message": f"Patched {os.path.basename(path)}: +{added} -{removed} lines across {len(hunks)} hunk(s).",
            "data": {"path": path, "added": added, "removed": removed, "hunks": len(hunks)}
        }

    # =====================================
    # RUN
    # =====================================
    def run(
        self,
        input_text: str,
        action: str = None,
        parameters: dict = None
    ) -> dict:

        try:

            parameters = (
                parameters
                or {}
            )

            if not action:

                return {

                    "success": False,

                    "message":
                    "No file action "
                    "specified.",

                    "data": {}
                }

            if action == (
                "create_file"
            ):

                return self.create_file(

                    parameters.get(
                        "path",
                        ""
                    )
                )

            elif action == (
                "delete_file"
            ):

                return self.delete_file(

                    parameters.get(
                        "path",
                        ""
                    )
                )

            elif action == (
                "list_files"
            ):

                return self.list_files(

                    parameters.get(
                        "path",
                        "."
                    )
                )

            elif action == (
                "open_file"
            ):

                return self.open_file(

                    parameters.get(
                        "path",
                        ""
                    )
                )

            elif action == "read_document":
                return self.read_document(
                    parameters.get("path", ""),
                    parameters.get("max_chars", 8000)
                )

            elif action == "summarize_document":
                return self.summarize_document(
                    parameters.get("path", "")
                )

            elif action == "apply_patch":
                return self.apply_patch(
                    parameters.get("path", ""),
                    parameters.get("diff", parameters.get("diff_text", ""))
                )

            # Phase 58 — RAG (chat with your documents)
            elif action == "index_docs":
                from core import rag
                p = parameters.get("path", "")
                p_exp = os.path.expanduser(p)
                return rag.index_folder(p) if os.path.isdir(p_exp) else rag.index_file(p)

            elif action == "ask_docs":
                from core import rag
                return rag.ask(parameters.get("query", input_text))

            elif action == "docs_status":
                from core import rag
                s = rag.stats()
                if not s["passages"]:
                    return {"success": True, "message": "No documents indexed yet, boss.", "data": s}
                return {"success": True,
                        "message": f"{s['documents']} document(s) indexed, {s['passages']} passages ready.",
                        "data": s}

            elif action == "clear_docs":
                from core import rag
                return rag.clear()

            return {

                "success": False,

                "message":
                f"Unsupported "
                f"file action: "
                f"{action}",

                "data": {}
            }

        except Exception as e:

            return {

                "success": False,

                "message":
                f"File agent error: "
                f"{str(e)}",

                "data": {}
            }


file_agent = FileAgent()