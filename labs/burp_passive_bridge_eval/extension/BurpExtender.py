# Burp legacy Extender API / Jython 2.7. No listeners, scanner, or HTTP client.
from burp import IBurpExtender, IContextMenuFactory
from java.util import ArrayList
from java.nio.file import Files, Paths
from java.nio.file.attribute import PosixFilePermissions
from javax.swing import JMenuItem, JOptionPane
import base64
import hashlib
import json
import re

LIMIT = 16 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_transfer(project, entries):
    payload = {"schema": "bbtk.burp-passive/1", "project": project, "entries": entries}
    data = canonical({"payload": payload, "sha256": hashlib.sha256(canonical(payload)).hexdigest()})
    if len(data) > LIMIT:
        raise ValueError("File limit")
    return data


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("bbtk passive private export")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        items = ArrayList()
        items.add(JMenuItem("bbtk: export selected privately", actionPerformed=lambda event: self.export(messages)))
        return items

    def export(self, messages):
        temporary = None
        try:
            if not 1 <= len(messages) <= 100:
                raise ValueError("Selection count")
            project = JOptionPane.showInputDialog(None, "Authorized bbtk project slug:")
            if project is None:
                return
            if not re.match(r"^[a-z0-9][a-z0-9._-]{0,63}$", project):
                raise ValueError("Project")
            scope = JOptionPane.showInputDialog(
                None, "Exact allowed origins, separated by commas (also checked against Burp scope):"
            )
            if scope is None:
                return
            allowed = set(value.strip().rstrip("/") for value in scope.split(","))
            entries, seen = [], set()
            rejected = duplicates = 0
            helpers = self.callbacks.getHelpers()
            for message in messages:
                service = message.getHttpService()
                protocol, host, port = service.getProtocol(), service.getHost(), service.getPort()
                if ":" in host and not host.startswith("["):
                    host = "[" + host + "]"
                origin = protocol + "://" + host.lower()
                if port != (443 if protocol == "https" else 80):
                    origin += ":" + str(port)
                request = message.getRequest()
                response = message.getResponse()
                url = helpers.analyzeRequest(message).getUrl()
                if origin not in allowed or not self.callbacks.isInScope(url) or request is None:
                    rejected += 1
                    continue
                # bytesToString is a reversible ISO-8859-1 mapping in Burp's helper API.
                raw_request = helpers.bytesToString(request).encode("iso-8859-1")
                raw_response = None if response is None else helpers.bytesToString(response).encode("iso-8859-1")
                if len(raw_request) > 1000000 or (raw_response is not None and len(raw_response) > 1000000):
                    rejected += 1
                    continue
                try:
                    raw_request.decode("utf-8")
                    if raw_response is not None:
                        raw_response.decode("utf-8")
                except UnicodeError:
                    rejected += 1
                    continue
                entry = {
                    "origin": origin,
                    "timestamp": None,
                    "request": base64.b64encode(raw_request),
                    "response": None if raw_response is None else base64.b64encode(raw_response),
                }
                key = canonical(entry)
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
                entries.append(entry)
            preview = (
                "Selected: %d; unique: %d; duplicates: %d; rejected: %d.\nPRIVATE file contains credentials. Authorize manual export?"
                % (len(messages), len(entries), duplicates, rejected)
            )
            if (
                not entries
                or JOptionPane.showConfirmDialog(None, preview, "bbtk preview", JOptionPane.YES_NO_OPTION)
                != JOptionPane.YES_OPTION
            ):
                return
            destination = JOptionPane.showInputDialog(
                None, "New absolute file in an existing owner-only 0700 directory outside Git (POSIX only):"
            )
            if destination is None:
                return
            path = Paths.get(destination)
            if not path.isAbsolute() or path.normalize() != path or Files.exists(path):
                raise ValueError("Destination")
            parent = path.getParent()
            cursor = parent
            while cursor is not None:
                if Files.isSymbolicLink(cursor) or Files.exists(cursor.resolve(".git")):
                    raise ValueError("Unsafe ancestor")
                cursor = cursor.getParent()
            if PosixFilePermissions.toString(Files.getPosixFilePermissions(parent)) != "rwx------":
                raise ValueError("Private parent required")
            if Files.getOwner(parent) != Files.getOwner(Paths.get(java_home())):
                raise ValueError("Owner mismatch")
            data = build_transfer(project, entries)
            attribute = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
            temporary = Files.createTempFile(parent, ".bbtk-", ".tmp", attribute)
            Files.write(temporary, helpers.stringToBytes(data.decode("iso-8859-1")))
            # Hard-link publication is atomic and refuses an existing destination.
            Files.createLink(path, temporary)
            JOptionPane.showMessageDialog(
                None, "Private export complete. Import explicitly with bbtk's offline bridge module."
            )
        except Exception:
            JOptionPane.showMessageDialog(
                None, "Export refused. Review selection, limits, POSIX permissions and destination locally."
            )
        finally:
            if temporary is not None:
                Files.deleteIfExists(temporary)


def java_home():
    from java.lang import System

    return System.getProperty("user.home")
