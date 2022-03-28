# Rover extension for the gemini protocol.
#
# Heavily influenced by AV98 (https://tildegit.org/solderpunk/AV-98).
# Code in this module, specifically send_request, get_addresses, was lifted from AV98. Here's
# AV98's licencse information.
#
#   Copyright (c) 2020, Solderpunk <solderpunk@sdf.org> and contributors.
#   All rights reserved.
#   
#   Redistribution and use in source and binary forms, with or without modification,
#   are permitted provided that the following conditions are met:
#   
#       1. Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#   
#       2. Redistributions in binary form must reproduce the above copyright notice,
#       this list of conditions and the following disclaimer in the documentation
#       and/or other materials provided with the distribution.
#   
#       THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#       AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#       IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#       ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#       LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#       DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#               SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#       CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#       OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
#       USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Note there are limitations when using this rover protocol.
#  1) Submission is not supported.
#  2) Directories are gem text files.
#  3) Only UTF-8 is supported.

import sys
import urllib.parse
import importlib
import ssl
import socket
import cgi
import os
import codecs
from typing import NamedTuple # Requires python 3.6
from pathlib import Path
from ssl import CertificateError

_DEBUG = False
_TIMEOUT = 10
_MAX_REDIRECTS = 5

urllib.parse.uses_relative.append("gemini")
urllib.parse.uses_netloc.append("gemini")

# Load rover.py. A bit handwavy but basically boils down to 'import ../rovery.py'
script_path = Path(os.path.realpath(__file__)).parent.parent
rover_utility_spec = importlib.util.spec_from_file_location("rover", script_path / "rover.py")
rover_utility = importlib.util.module_from_spec(rover_utility_spec)
rover_utility_spec.loader.exec_module(rover_utility)

absolutise_url = urllib.parse.urljoin
parse_url = urllib.parse.urlparse

eprint = rover_utility.eprint
wprint = rover_utility.wprint

def dprint(*args, **kwargs):
    if _DEBUG:
        print("DBG:", *args, file=sys.stdout, **kwargs)

class GeminiFile(NamedTuple):
    url: str
    body: bytes
    mime: str
    mime_options: dict
    encoding: str

def api_canonicalize_url(url: str):
    return url

def api_use_abspath():
    return True

def api_land_file(url, local_path):
    file = get_gemini_file(url, set(url))
    body = getattr(file, 'body')
    mime = getattr(file, 'mime')
    mime_options = getattr(file, 'mime_options')

    if not mime.startswith("text/"):
        if "charset" not in mime_options.keys():
            wprint(f"Unable to determine if mime ('{mime}') has UTF-8 charset")
            raise RuntimeError(f"Unable to determine if content ('{mime}') is UTF-8 encoded")
        if mime_options.get("charset").lower() != "utf-8":
            charset = mime_options.get("charset")
            wprint(f"Charset ('{charset}') not supported. Only UTF-8 is supported.")
            raise RuntimeError(f"Unsupported charset {charset}")

    if mime.startswith("text/"):
        charset = mime_options.get("charset", "UTF-8")
        if charset.lower() != "utf-8":
            raise RuntimeError(f"Unsupported charset {charset}")

    with open(local_path, "w") as f:
        f.write(body.decode("utf-8"))

def api_get_rover_file_from_url(url_in: str):
    # If the URL is a gemini file, treat the gemini file per the gmisub spec.
    # gemini://gemini.circumlunar.space/docs/companion/subscription.gmi
    file = get_gemini_file(url_in, set(url_in))
    url = getattr(file, 'url')

    # TODO Include atom files.
    if not getattr(file, 'mime') == 'text/gemini':
        eprint("Only gemtext is supported as rover directories.")
        sys.exit(1)

    try:
        body = getattr(file, 'body').decode(getattr(file,'encoding'))
    except UnicodeError:
        eprint("Could not decode response body using {encoding} encoding declared in header!")
        sys.exit(1)

    empty_sha = "0000000000000000000000000000000000000000000000000000000000000000"
    files = [rover_utility.FileEntry(empty_sha,0,0,1,url,"")]

    # Search for links and add them as 'files'
    for line in body.splitlines():
        if line.startswith("=>"):
            # For gemini, we don't take the sha of the files until we download them.
            # This is somewhat problematic as we won't be able to detect what changed.
            # We treat a sha of 0 specially.
            assert line[2:].strip()
            bits = line[2:].strip().split(maxsplit=1)
            if len(parse_url(bits[0]).scheme) > 0:
                abs_path = 1
                file_url = bits[0]
            else:
                # All gemini urls are absolute paths. It's too complicated to keep
                # track of files that are in the same directory.
                abs_path = 1
                file_url = absolutise_url(url, bits[0])
            description = ""
            if len(bits) > 1:
                description = bits[1]
            if len(urllib.parse.urlparse(file_url).query) > 0:
                continue # Ignore URLs with query strings.
            file_entry = rover_utility.FileEntry(empty_sha,0,0,abs_path,file_url,description)
            # Only select files that have names.
            if len(rover_utility.FileEntry_get_filename_only(file_entry)) != 0:
                files.append(file_entry)

    ver = "0"   # No concept of versioning.
    dirs = []   # Directories don't really make sense with subscription formats like gmisub and atom.
    rover_file = rover_utility.RoverFile(url, ver, files, dirs)
    return rover_file

def api_submit_file(url: str, local_path: Path):
    eprint("submit not defined for gemini")
    sys.exit(1)

def api_delete_file(url: str, local_path: Path):
    eprint("File deletion not defined for gemini")
    sys.exit(1)

def api_mkdir(url: str):
    eprint("mkdir not defined for gemini")
    sys.exit(1)

def get_gemini_file(url: str, previous_redirectors: set):
    # If the URL is a gemini file, treat the gemini file per the gmisub spec.
    # gemini://gemini.circumlunar.space/docs/companion/subscription.gmi
    parsed_url = urllib.parse.urlparse(url)
    address, f = send_request(url)

    # Spec dictates <META> should not exceed 1024 bytes,
    # so maximum valid header length is 1027 bytes.
    header = f.readline(1027)
    header = header.decode("UTF-8")
    if not header or header[-1] != '\n':
        eprint("Received invalid header from server!")
        sys.exit(1)
    header = header.strip()
    #self._debug("Response header: %s." % header)

    status, meta = header.split(maxsplit=1)
    if len(meta) > 1024 or len(status) != 2 or not status.isnumeric():
        f.close()
        eprint("Received invalid header from server!")
        sys.exit(1)

    # Update redirect loop/maze escaping state
    if status.startswith("3"):
        new_url = absolutise_url(url, meta)
        if new_url == url:
            eprint("URL redirects to itself.")
            sys.exit(1)
        if new_url in previous_redirectors:
            eprint("Caught in redirection loop.")
            sys.exit(1)
        if len(previous_redirectors) == _MAX_REDIRECTS:
            eprint("Maximum number of redirects")
            sys.exit(1)
        if parse_url(new_url).hostname != parse_url(url).hostname:
            eprint("Cross-domain redirects not allowed.")
            sys.exit(1)
        if parse_url(new_url).scheme != parse_url(url).scheme:
            eprint("Cross-protocol redirects not implemented.")
            sys.exit(1)
        dprint(f"Following redirect to {new_url}")
        previous_redirectors.add(new_url)
        return get_gemini_file(new_url, previous_redirectors)

    # Handle non-SUCCESS headers, which don't have a response body
    # Inputs
    if status.startswith("1"):
        raise RuntimeError(f"Gemini input not supported. '{url}'")

    if status.startswith("4") or status.startswith("5"):
        raise RuntimeError(f"Server returned error. '{meta}' for '{url}'")

    # Client cert
    if status.startswith("6"):
        raise RuntimeError(f"Client cert not supported. '{url}'")

    if not status.startswith("2"):
        raise RuntimeError(f"Server returned an undefined status code '{status}'")

    mime = meta
    if mime == "":
        mime = "text/gemini; charset=UTF-8"
    mime, mime_options = cgi.parse_header(mime)
    if "charset" in mime_options:
        try:
            codecs.lookup(mime_options["charset"])
        except LookupError as e:
            eprint("Header declared unknown encoding {value}")
            raise e

    body = f.read()

    # Save the result in a temporary file
    if mime.startswith("text/"):
        encoding = mime_options.get("charset", "UTF-8")
    else:
        encoding = None

    return GeminiFile(url, body, mime, mime_options, encoding)

def get_addresses(host, port):
    # DNS lookup - will get IPv4 and IPv6 records if IPv6 is enabled
    if ":" in host:
        # This is likely a literal IPv6 address, so we can *only* ask for
        # IPv6 addresses or getaddrinfo will complain
        family_mask = socket.AF_INET6
    elif socket.has_ipv6:
        # Accept either IPv4 or IPv6 addresses
        family_mask = 0
    else:
        # IPv4 only
        family_mask = socket.AF_INET
    addresses = socket.getaddrinfo(host, port, family=family_mask, type=socket.SOCK_STREAM)
    # Sort addresses so IPv6 ones come first
    addresses.sort(key=lambda add: add[0] == socket.AF_INET6, reverse=True)

    return addresses

def send_request(url: str):
    """Send a selector to a given host and port.
    Returns the resolved address and binary file with the reply."""
    standard_ports = {
            "gemini": 1965,
    }
    CRLF = '\r\n'

    parsed_url = urllib.parse.urlparse(url)
    host = parsed_url.hostname
    port = parsed_url.port or standard_ports.get(parsed_url.scheme, 0)
    host = parsed_url.hostname

    # Do DNS resolution
    addresses = get_addresses(host, port)

    # Prepare TLS context
    protocol = ssl.PROTOCOL_TLS if sys.version_info.minor >=6 else ssl.PROTOCOL_TLSv1_2
    context = ssl.SSLContext(protocol)
    # Use TOFU
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Impose minimum TLS version
    ## In 3.7 and above, this is easy...
    if sys.version_info.minor >= 7:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    ## Otherwise, it seems very hard...
    ## The below is less strict than it ought to be, but trying to disable
    ## TLS v1.1 here using ssl.OP_NO_TLSv1_1 produces unexpected failures
    ## with recent versions of OpenSSL.  What a mess...
    else:
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_SSLv2
    # Try to enforce sensible ciphers
    try:
        context.set_ciphers("AESGCM+ECDHE:AESGCM+DHE:CHACHA20+ECDHE:CHACHA20+DHE:!DSS:!SHA1:!MD5:@STRENGTH")
    except ssl.SSLError:
        # Rely on the server to only support sensible things, I guess...
        pass

    # Connect to remote host by any address possible
    err = None
    for address in addresses:
        dprint("Connecting to: " + str(address[4]))
        s = socket.socket(address[0], address[1])
        s.settimeout(_TIMEOUT)
        s = context.wrap_socket(s, server_hostname = host)
        try:
            s.connect(address[4])
            break
        except OSError as e:
            err = e
        except Exception as e:
            err = e
    else:
        # If we couldn't connect to *any* of the addresses, just
        # bubble up the exception from the last attempt and deny
        # knowledge of earlier failures.
        raise err

    if sys.version_info.minor >=5:
        dprint("Established {} connection.".format(s.version()))
    dprint("Cipher is: {}.".format(s.cipher()))

    # Do TOFU
    cert = s.getpeercert(binary_form=True)
    # TODO Not validating the cert. Need to address this.
    #self._validate_cert(address[4][0], host, cert)

    # Send request and wrap response in a file descriptor
    dprint("Sending %s<CRLF>" % url)
    s.sendall((url + CRLF).encode("UTF-8"))
    return address, s.makefile(mode = "rb")
