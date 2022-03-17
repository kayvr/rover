#!/usr/bin/env python3
# Copyright (c) 2022, kayvr <kayvr@>

# Standard library imports.
import sys
import argparse
import hashlib
import urllib.parse
import os
import string
import shutil
import pydoc
import importlib
import types
import typing
import time
import configparser
from typing import NamedTuple # Requires python 3.6
from pathlib import Path

# .ROVER File structure.
class FileEntry(NamedTuple): # fil
    sha: str
    ver: str
    key: str
    abs_path: str # Non-zero if filename is an absolute path (think symlink).
    filename: str
    metadata: str

class DirEntry(NamedTuple):
    key: str
    filename: str
    metadata: str

class RoverFile(NamedTuple):
    url: str
    ver: str
    files: list             # List of FileEntry
    directories: list       # List of DirEntry

def FileEntry_get_filename_only(file_entry: FileEntry):
    if getattr(file_entry, "abs_path") != "0":
        parsed_url = urllib.parse.urlparse(getattr(file_entry, "filename"))
        return Path(parsed_url.path).name

    return getattr(file_entry, "filename")

subcommand_names = ["status","land","fetch","tour","submit","url"]
verbose = False
parse_url = urllib.parse.urlparse
empty_sha = "0000000000000000000000000000000000000000000000000000000000000000"

rover_file_url_prefix       = "url "
rover_file_version_prefix   = "ver "
rover_file_file_prefix      = "fil "
rover_file_directory_prefix = "dir "

TourOperationType_Status = 1
TourOperationType_Print  = 2

class SupportedProtocol(NamedTuple):
    name : str
    module : types.ModuleType
    spec : typing.Any

loaded_protocols = set()
supported_protocols = {
        "file": SupportedProtocol("file", None, None),
        }

ignored_protocol_dirs = [
        "test",
        "__pycache__"
        ]

# Detect all supported protocols.
rover_script_path = os.path.realpath(__file__)
for entry in Path(rover_script_path).parent.iterdir():
    if entry.is_dir() and entry.name not in ignored_protocol_dirs and not entry.name.startswith('.'):
        entry = Path(entry)
        spec = importlib.util.spec_from_file_location(entry.name, entry / f"{entry.name}.py")
        module = importlib.util.module_from_spec(spec)
        supported_protocols[entry.name] = SupportedProtocol(entry.name, module, spec)
        if entry.name not in urllib.parse.uses_relative:
            urllib.parse.uses_relative.append(entry.name)
            urllib.parse.uses_netloc.append(entry.name)


# Implementation of the 'file://' protocol.
class FileProtocol:
    @staticmethod
    def api_use_abspath():
        return False

    @staticmethod
    def api_land_file(url: str, local_path: Path):
        parsed_url = parse_url(url)
        source_path = Path(parsed_url.path)
        source_rover_file = source_path.parent / ".rover"
        if source_rover_file.is_file():
            eprint(f"Source directory '{source_path}' must not contain a .rover file.")
            sys.exit(1)

        shutil.copyfile(source_path, local_path)

    @staticmethod
    def api_get_rover_file_from_url(url: str):
        return generate_rover_file_from_path(parse_url(url).path)

    @staticmethod
    def api_submit_file(url: str, local_path: Path):
        destination = parse_url(url).path / Path(local_path.name)
        shutil.copyfile(local_path, destination)

    @staticmethod
    def api_delete_file(url: str, local_path: Path):
        print("api_delete_file: TODO")

    @staticmethod
    def api_mkdir(url: str):
        print("api_mkdir: TODO")

def get_protocol(url: str):
    scheme = parse_url(url).scheme
    if scheme not in supported_protocols.keys():
        print(f"Failed to find protocol '{scheme}'")
        raise RuntimeError(f"Failed to find protocol '{scheme}'")
    protocol = supported_protocols[scheme]
    if protocol.name == "file":
        file_module = FileProtocol()
        return file_module
    if protocol.name not in loaded_protocols:
        protocol.spec.loader.exec_module(protocol.module)
        loaded_protocols.add(protocol.name)
    return protocol.module

def api_use_abspath(url: str):
    protocol = get_protocol(url)
    return protocol.api_use_abspath()

def api_land_file(url: str, local_path: Path):
    if verbose:
        start = time.time()
    protocol = get_protocol(url)
    protocol.api_land_file(url, local_path)
    if verbose:
        duration = time.time() - start
        print(f"API Call [{duration:5.2}s]: api_land_file {url}", file=sys.stderr)

def api_submit_file(url: str, local_path: Path):
    if verbose:
        start = time.time()
    protocol = get_protocol(url)
    protocol.api_submit_file(url, local_path)
    if verbose:
        duration = time.time() - start
        print(f"API Call [{duration:5.2}s]: api_submit_file {url}", file=sys.stderr)

def api_delete_file(url: str, local_path: Path):
    if verbose:
        start = time.time()
    protocol = get_protocol(url)
    protocol.api_delet_file(url, local_path)
    if verbose:
        duration = time.time() - start
        print(f"API Call [{duration:5.2}s]: api_delete_file {url}", file=sys.stderr)

# During a tour this function is called many times per process instance.
# Since this process is temporary, I feel better about caching.
rover_file_from_url_cache = {}
def api_get_rover_file_from_url(url: str):
    global rover_file_from_url_cache
    if verbose:
        start = time.time()
    protocol = get_protocol(url)
    if url not in rover_file_from_url_cache:
        retval = protocol.api_get_rover_file_from_url(url)
        rover_file_from_url_cache[url] = retval
    else:
        retval = rover_file_from_url_cache[url]
    if verbose:
        duration = time.time() - start
        print(f"API Call [{duration:5.2}s]: get_rover_file_from_url {url}", file=sys.stderr)
    return retval

def invalidate_caches():
    global rover_file_from_url_cache
    rover_file_from_url_cache = {}

# RoverDirModInfo contains directory modification information.
class RoverDirModInfo(NamedTuple):
    url : str
    local_path : str
    remote_modified_files : list
    remote_added_files : list
    remote_added_dirs : list
    remote_deleted_files : list
    remote_deleted_dirs : list
    local_modified_files : list
    local_deleted_files : list
    local_added_files : list

def eprint(*args, **kwargs):
    print("ERROR:", *args, file=sys.stderr, **kwargs)

def read_integer(line):
    index = 0
    integer_str = ""
    while index < len(line) and line[index] in string.digits:
        integer_str = integer_str + line[index]
        index = index + 1
    if len(line) + 1 <= index: # + 1 for space
        eprint(f"Unexpected integer for argument: {line}.")
        sys.exit(1)
    line = line[len(integer_str):]
    if line[0] != ' ':
        eprint(f"Expected space after argument: {line}.")
        sys.exit(1)
    line = line[1:]
    return line,integer_str

def read_rover_config(section):
    config_path = Path.home() / ".config" / "rover" / "rover.ini"
    if not config_path.exists() or not config_path.is_file():
        return {}

    config = configparser.ConfigParser()
    config.read(config_path)

    return dict(config.items(section))

def read_rover_file(path):
    with open(path, encoding="utf-8") as f:
        url = f.readline().strip()
        if not url.startswith(rover_file_url_prefix):
            raise RuntimeError(f"Expected 'url' directive as first line in .rover file: {path}")
        url = url[len(rover_file_url_prefix):]

        ver = f.readline().strip()
        if not ver.startswith(rover_file_version_prefix):
            raise RuntimeError(f"Expected 'ver' directive as second line in .rover file: {path}. Have: '{ver}'")
        ver = ver[len(rover_file_version_prefix):]

        line = f.readline().strip()
        files = []
        directories = []
        line_number = 0
        while line:
            if line.startswith(rover_file_file_prefix):
                line = line[len(rover_file_file_prefix):]

                sha256 = ""
                filename = ""

                sha256_length = 64
                if len(line) < sha256_length + 1:
                    raise RuntimeError(f"Unexpected first argument for 'fil' directive: {line}")
                sha256 = line[0:sha256_length]
                line = line[sha256_length + 1:]

                line,version = read_integer(line)
                line,key = read_integer(line)
                line,abs_path = read_integer(line)

                line = line.strip()
                if len(line) == 0:
                    raise RuntimeError(f"Expected filename")

                halves = line.strip().split(maxsplit=1)
                filename = urllib.parse.unquote(halves[0])
                metadata = ""
                if len(halves) > 1:
                    metadata = halves[1]

                files.append(FileEntry(sha256, version, key, abs_path, filename, metadata))
            elif line.startswith(rover_file_directory_prefix):
                line = line[len(rover_file_directory_prefix):]
                line,version = read_integer(line)

                line = line.strip()
                if len(line) == 0:
                    raise RuntimeError(f"Expected directory name")

                halves = line.strip().split(maxsplit=1)
                filename = urllib.parse.unquote(halves[0])
                metadata = ""
                if len(halves) > 1:
                    metadata = halves[1]

                directories.append(DirEntry(version, filename, metadata))
            else:
                raise RuntimeError(f"Unexpected .rover file directive: {line}")
            line_number = line_number + 1
            line = f.readline().strip()
        return RoverFile(url,ver,files,directories)

def write_rover_file(path, rover_file):
    rover_path = Path(path) / ".rover"
    with open(rover_path, "w", encoding="utf-8") as f:
        f.write(f"url {getattr(rover_file, 'url')}\n")
        f.write(f"ver {getattr(rover_file, 'ver')}\n")
        for file in getattr(rover_file, 'files'):
            url_encoded_filename = urllib.parse.quote(getattr(file, 'filename'))
            f.write(f"fil {getattr(file, 'sha')} {getattr(file, 'ver')} {getattr(file, 'key')} {getattr(file, 'abs_path')} {url_encoded_filename} {getattr(file, 'metadata')}\n")
        for dir in getattr(rover_file, 'directories'):
            url_encoded_filename = urllib.parse.quote(getattr(dir, 'filename'))
            f.write(f"dir {getattr(dir, 'key')} {url_encoded_filename} {getattr(dir, 'metadata')}\n")

# Regardless of the existence of a rover file at 'source_path', generate a rover
# file for 'source_path' without writing it to disk.
def generate_rover_file_from_path(source_path):
    source_path = Path(source_path)
    if not source_path.is_dir():
        eprint("source_path must be a directory in order to generate rover file.")
        sys.exit(1)
    files = []
    directories = []
    for item in source_path.iterdir():
        if item.is_file():
            try:
                file_contents = open(item, 'r', encoding="utf-8").read()
                sha = hashlib.sha256(file_contents.encode('utf-8')).hexdigest()
            except UnicodeDecodeError as e:
                print(f"Ignoring invalid utf-8 file. {item} {e}")
                continue
            stat = os.stat(item)
            mtime = int(os.path.getmtime(item))
            abs_path = 0 # Symlinks not supported in local fs.
            metadata = ""
            files.append(FileEntry(sha, str(mtime), str(stat.st_ino), abs_path, item.name, metadata))
        elif item.is_dir():
            stat = os.stat(item)
            metadata = ""
            directories.append(DirEntry(str(stat.st_ino), item.name, metadata))

    mtime = int(os.path.getmtime(source_path))
    
    rover_file = RoverFile(
            "file://" + str(source_path) + "/", # Directory postfix is /.
            mtime,
            files,
            directories)

    return rover_file

def path_to_url(path_or_url):
    # Early out when protocol is explicitly specified.
    if any(path_or_url.startswith(f"{k}://") for k in supported_protocols.keys()):
        return path_or_url

    # XXX The following logic could do with some simplification. This function
    #     is only used for 'rover land' and was rolled early in development.
    path_to_rover_file = None
    rover_file_entry = ""
    if path_or_url == '.':
        path_to_rover_file = Path.cwd() / ".rover"
    else:
        # Interpret the url as a path.
        path = Path(path_or_url)
        if path.is_dir():
            path_to_rover_file = path / ".rover"
            if not path_to_rover_file.is_file():
                # Check to see whether this directory is included in the .rover file in the parent's directory.
                rover_file_entry = path.name
                path_to_rover_file = path.parent.absolute() / ".rover"
                if not path_to_rover_file.is_file():
                    # Since no rover file is found, interpret absolute paths as a
                    # file checkout.
                    if os.path.isabs(path):
                        # Assume the user wants to use the file:// protocol.
                        return "file://" + path_or_url
                    eprint(f"Have directory '{path}' but no rover file found in the directory or parent directory.")
                    sys.exit(1)
                rover_file = read_rover_file(path_to_rover_file)
                all_directory_names = [getattr(x,'filename') for x in rover_file.directories]
                if not path.name in all_directory_names:
                    eprint(f"Directory '{path.name}' not found in {path_to_rover_file}")
                    sys.exit(1)
        elif path.is_file():
            path_to_rover_file = path.parent.absolute() / ".rover"
            rover_file_entry = path.name
        else:
            # First, check if the path is absolute. We interpret absolute,
            # non-existent, paths as file:// lands.
            if os.path.isabs(path):
                return "file://" + path_or_url
            # Check if the parent of the file that doesn't exist includes a .rover file.
            path_to_rover_file = path.parent.absolute() / ".rover"
            rover_file_entry = path.name
            rover_file = read_rover_file(path_to_rover_file)
            in_rover_directories = rover_file_entry in rover_file.directories
            in_rover_files = False
            for file in rover_file.files:
                if file.filename == rover_file_entry:
                    in_rover_files = True
                    break
            if not in_rover_directories and not in_rover_files:
                eprint(f"Directory/File '{path.name}' not found in {path_to_rover_file}")
                sys.exit(1)

    if not path_to_rover_file:
        eprint(f"Failed to canonicalize: {path_or_url}")
        sys.exit(1)

    if not path_to_rover_file.is_file():
        eprint("No '.rover' file not found at: '{path_to_rover_file}' from '{path_or_url}'")
        sys.exit(1)

    rover_file = read_rover_file(path_to_rover_file)

    if len(rover_file_entry) > 0:
        return getattr(rover_file, "url") + f"/{rover_file_entry}"
    else:
        return getattr(rover_file, "url")

def get_modified_files(path, rover_file):
    files_changed_locally = []
    for dir_element in path.iterdir():
        if dir_element.is_file():
            file_contents = open(dir_element, 'r', encoding='utf-8').read()
            sha256 = hashlib.sha256(file_contents.encode('utf-8')).hexdigest()
            for file in rover_file.files:
                if FileEntry_get_filename_only(file) == dir_element.name:
                    if getattr(file, "sha") != sha256:
                        files_changed_locally.append(dir_element.name)
                    break
    return files_changed_locally

def get_deleted_files(path, rover_file):
    remote_missing_files = []
    local_files_and_dirs = set()
    for dir_element in path.iterdir():
        local_files_and_dirs.add(dir_element.name)
    for file in rover_file.files:
        if FileEntry_get_filename_only(file) not in local_files_and_dirs:
            remote_missing_files.append(FileEntry_get_filename_only(file))
    return remote_missing_files

def get_untracked_files(path, rover_file):
    remote_files_and_dirs = set()
    for file in rover_file.files:
        remote_files_and_dirs.add(FileEntry_get_filename_only(file))
    for d in rover_file.directories:
        remote_files_and_dirs.add(getattr(d, "filename"))
    locally_added_files = []
    for file in path.iterdir():
        if file.name == ".rover":
            continue
        if file.name not in remote_files_and_dirs:
            locally_added_files.append(file.name)
    return locally_added_files

def protocol_perform_land(
        protocol: SupportedProtocol,
        url: str,
        target_path: Path,
        paths_to_exclude: set,
        is_recursive: bool,
        leave_for_tour: bool):
    dest_rover_file_path = target_path / ".rover"
    src_rover_file = api_get_rover_file_from_url(url)
    original_files = []
    if not dest_rover_file_path.exists():
        write_rover_file(dest_rover_file_path.parent, src_rover_file)
    else:
        original_files = getattr(read_rover_file(dest_rover_file_path), 'files')

    if not leave_for_tour:
        for file_entry in src_rover_file.files:
            file = getattr(file_entry, 'filename')
            if file not in paths_to_exclude:
                dest = target_path / Path(file).name
                land_file(dest)

    for dir_entry in src_rover_file.directories:
        d = getattr(dir_entry, 'filename')
        dest = target_path / Path(d)
        if not dest.exists():
            os.mkdir(dest) # Only create empty directories

    # Note: The destination rover file will have been updated through calls to land_file
    dest_rover_file = read_rover_file(dest_rover_file_path)

    if leave_for_tour:
        src_rover_file = RoverFile(
                getattr(src_rover_file, "url"),
                getattr(src_rover_file, "ver"),
                original_files,
                getattr(src_rover_file, "directories"))
    else:
        src_rover_file = dest_rover_file

    write_rover_file(target_path, src_rover_file)

    if is_recursive:
        for dir_entry in src_rover_file.directories:
            filename = getattr(dir_entry, 'filename')
            rec_url = getattr(src_rover_file, 'url')
            # Directories must support a forward slash after the name.
            if not rec_url.endswith("/"):
                print("Have url, that is a directory, that does not contain a terminating slash.")
                rec_url = rec_url + "/"
            rec_url_joined = urllib.parse.urljoin(rec_url, filename)
            protocol_on_land(protocol, rec_url_joined, target_path / filename, is_recursive, leave_for_tour)

def protocol_update_target(
        protocol: SupportedProtocol,
        url: str,
        target_path: Path,
        is_recursive: bool,
        leave_for_tour: bool):
    mod_info = get_rover_dir_mod_info(target_path)

    target_modified_files = getattr(mod_info, "local_modified_files")
    target_deleted_files = getattr(mod_info, "local_deleted_files")
    target_added_files = getattr(mod_info, "local_added_files")
    target_altered_files = set(target_modified_files) | set(target_deleted_files) | set(target_added_files)

    source_modified_files = getattr(mod_info, "remote_modified_files")
    source_deleted_files = getattr(mod_info, "remote_deleted_files")
    source_added_files = getattr(mod_info, "remote_added_files")
    source_altered_files = set(source_modified_files) | set(source_deleted_files) | set(source_added_files)

    union_altered_files = set(target_altered_files) & set(source_altered_files)
    if len(union_altered_files) > 0:
        eprint(f"Source directory and destination directory have altered the same files.")
        eprint(f"  Source:    '{url}'")
        eprint(f"  Dest:      '{target_path}'")
        eprint(f"  Conlficts: '{union_altered_files}'")
        eprint(f"Aborting update.")
        sys.exit(1)

    # There are no altered files in common between the two directories. Copy
    # files in the source path to the destination path.
    protocol_perform_land(protocol, url, target_path, target_altered_files, is_recursive, leave_for_tour)

def protocol_on_land(
        protocol: SupportedProtocol,
        url: str,
        target_path: Path,
        is_recursive: bool,
        leave_for_tour: bool):

    if target_path.is_file():
        eprint(f"Land operates on directories. For individual files use fetch.")
        sys.exit(1)

    target_rover_file = target_path / ".rover"
    target_path_is_a_dir_and_non_empty = (target_path.is_dir() and len(os.listdir(target_path)) != 0)
    if target_path_is_a_dir_and_non_empty and target_rover_file.is_file():
        protocol_update_target(protocol, url, target_path, is_recursive, leave_for_tour)
    else:
        if target_path_is_a_dir_and_non_empty:
            eprint(f"Directory '{target_path}' is not empty and has no rover file.")
            sys.exit(1)

        if not target_path.is_dir():
            os.mkdir(target_path)

        protocol_perform_land(protocol, url, target_path, set(), is_recursive, leave_for_tour)

def handle_status(args):
    path = Path(args.path)

    rover_file_path = path / ".rover"
    if not rover_file_path.is_file():
        eprint(f"Unable to stat '{rover_file_path}'. No rover file exists.")
        sys.exit(1)

    is_recursive = False
    recursive_rel_path = ""
    if not args.recursive is None:
        if args.recursive == True:
            is_recursive = True
            recursive_rel_path = "."
    do_status(path, is_recursive, recursive_rel_path)

def handle_fetch(args):
    for path in args.path:
        path = Path(path)
        if path.is_dir():
            eprint("Fetch works on individual files.")
            sys.exit(1)

        rover_file = Path(path.parent) / ".rover"
        if not rover_file.exists():
            eprint(f"Parent directory for file does not contain a rover file. {path}")
            sys.exit(1)

        if not args.retour or not bool(args.retour):
            land_file(path)
        else:
            mark_for_tour(path)

def handle_land(args):
    url_or_path = args.url_or_path[0]
    url = path_to_url(url_or_path)

    parsed_url = urllib.parse.urlparse(url)
    target_path = None
    if url_or_path == ".":
        target_path = Path.cwd()
        if args.target_path is not None:
            eprint(f"Unexpected target_path argument. target_path: '{args.target_path}'")
            sys.exit(1)
    elif args.target_path is not None:
        target_path = Path(args.target_path)
        if target_path.exists():
            eprint(f"target_path argument already exists as a file or directory. target_path '{args.target_path}'")
            sys.exit(1)
        target_path.mkdir(parents=True, exist_ok=True)

    leave_for_tour = False
    if args.retour is not None and bool(args.retour):
        leave_for_tour = True

    if not parsed_url.scheme in supported_protocols.keys():
        eprint(f"Unsupported protocol: {parsed_url.scheme}")
        sys.exit(1)

    if target_path == None:
        target_path = Path.cwd() / Path(parsed_url.path).name

    protocol_on_land(supported_protocols[parsed_url.scheme], url, target_path, args.recursive, leave_for_tour)

    print(f"Land complete")

def handle_tour(args):
    if not args.path:
        target_path = Path.cwd()
    else:
        target_path = args.path

    if target_path == ".":
        target_path = Path.cwd()

    target_path = Path(target_path)

    if not target_path.exists():
        eprint(f"target_path must exist to execute a tour. '{target_path}'")
        sys.exit(1)

    if not target_path.is_dir():
        eprint(f"Tours support directories only. '{target_path}'")
        sys.exit(1)

    tour_operation = TourOperationType_Print
    if args.status:
        tour_operation = TourOperationType_Status

    # Call out to tour mechanism based on the URL in the .rover file.
    is_recursive = True
    recursive_rel_path = "."
    do_tour(target_path, tour_operation, is_recursive, recursive_rel_path)

def handle_submit(args):
    if not args.path:
        target_path = Path.cwd()
    else:
        target_path = args.path

    if target_path == ".":
        target_path = Path.cwd()

    target_path = Path(target_path)

    if not target_path.exists():
        eprint(f"target_path must exist to execute a tour. '{target_path}'")
        sys.exit(1)

    is_recursive = True if args.recursive else False
    do_submit(target_path, is_recursive)

    print(f"Submit complete")

def handle_url(args):
    if not args.path:
        eprint("Paths to convert must be given")
        sys.exit(1)

    for path in args.path:
        path = Path(path)
        if path.is_dir():
            eprint("'url' subcommand operates on individual files.")
            sys.exit(1)

        rover_file = Path(path.parent) / ".rover"
        if not rover_file.exists():
            eprint(f"Parent directory for file does not contain a rover file. {path}")
            sys.exit(1)

        target_path = path.parent
        rover_file_path = target_path / ".rover"
        if not rover_file_path.exists():
            eprint(f"'url': did not find rover file where land is being attempted. '{target_path}'")
            sys.exit(1)

        local_rover_file = read_rover_file(rover_file_path)
        url = getattr(local_rover_file, "url")
        parsed_url = urllib.parse.urlparse(url)

        if parsed_url.scheme not in supported_protocols.keys():
            eprint(f"Unable to obtain url file: unsupported protocol '{parsed_url.scheme}'")
            sys.exit(1)

        # XXX Note the code duplication with land_file.
        # Special case for and abspath protocols. We have no guarantees of where
        # files are located when using full URLs.
        file_url = ""
        url_metadata = ""
        is_absolute_url = False
        found_file = False
        file_url = urllib.parse.urljoin(url, path.name)
        for file in getattr(local_rover_file, "files"):
            if FileEntry_get_filename_only(file) == path.name:
                found_file = True
                if getattr(file, "abs_path") != "0":
                    # Purposfully do NOT use FileEntry_get_filename
                    file_url = getattr(file, "filename")
                    url_metadata = getattr(file, "metadata")
                    is_absolute_url = True
                break
        if not found_file and api_use_abspath(url):
            # Why this special case is needed: rover tour returns files that
            # have been added on the remote. It returns paths to local files
            # only. If a protocol uses absolute paths, then we can't reliably
            # reconstruct the URL from the URL in the .rover file and the
            # filename only.
            remote_rover_file = api_get_rover_file_from_url(url)
            for file in getattr(remote_rover_file, "files"):
                if FileEntry_get_filename_only(file) == path.name:
                    file_url = getattr(file, "filename")
                    url_metadata = getattr(file, "metadata")
                    break

        if args.metadata:
            print(url_metadata)
        else:
            print(file_url)

def get_rover_dir_mod_info(target_path):
    rover_file_path = target_path / ".rover"
    if not rover_file_path.exists():
        eprint(f"mod_info: Must begin in a directory that contains a rover file. '{target_path}'")
        sys.exit(1)

    local_rover_file = read_rover_file(rover_file_path)
    remote_rover_file = api_get_rover_file_from_url(local_rover_file.url)

    # Create dictionary from files in local_rover_file
    local_file_dict = {}
    local_dir_dict = {}
    remote_file_dict = {}
    remote_dir_dict = {}
    for file in local_rover_file.files:
        local_file_dict[FileEntry_get_filename_only(file)] = file
    for d in local_rover_file.directories:
        local_dir_dict[getattr(d, "filename")] = d
    for file in remote_rover_file.files:
        remote_file_dict[FileEntry_get_filename_only(file)] = file
    for d in remote_rover_file.directories:
        remote_dir_dict[getattr(d, "filename")] = d

    remote_modified_files = []
    remote_added_files = []
    remote_added_dirs = []
    for remote_file in remote_rover_file.files:
        remote_filename = FileEntry_get_filename_only(remote_file)
        if remote_filename in local_file_dict:
            local_file = local_file_dict[remote_filename]
            local_sha = getattr(local_file, "sha")
            remote_sha = getattr(remote_file, "sha")
            if local_sha != remote_sha and remote_sha != empty_sha:
                remote_modified_files.append(remote_filename)
        else:
            remote_added_files.append(remote_filename)
    for remote_dir in remote_rover_file.directories:
        remote_filename = getattr(remote_dir, "filename")
        if remote_filename in local_dir_dict:
            remote_added_dirs.append(remote_filename)

    local_modified_files = get_modified_files(target_path, local_rover_file)
    local_deleted_files = get_deleted_files(target_path, local_rover_file)
    local_added_files = get_untracked_files(target_path, local_rover_file)
    remote_deleted_files = []
    remote_deleted_dirs = []
    for local_file in local_rover_file.files:
        local_filename = FileEntry_get_filename_only(local_file)
        if local_filename not in remote_file_dict:
            remote_deleted_files.append(local_filename)
    for local_dir in local_rover_file.directories:
        local_filename = getattr(local_dir, "filename")
        if local_filename not in remote_dir_dict:
            remote_deleted_dirs.append(local_filename)

    return RoverDirModInfo(
            getattr(local_rover_file, "url"),
            str(target_path),
            remote_modified_files,
            remote_added_files,
            remote_added_dirs,
            remote_deleted_files,
            remote_deleted_dirs,
            local_modified_files,
            local_deleted_files,
            local_added_files)

def do_tour_recursion(target_path, operation_type, is_recursive, recursive_rel_path):
    if is_recursive:
        for entry in target_path.iterdir():
            if entry.is_dir():
                if len(os.listdir(entry)) > 0:
                    do_tour(entry, operation_type, is_recursive, f"{recursive_rel_path}/{entry.name}")

def do_tour(target_path, operation_type, is_recursive, recursive_rel_path):
    rover_file_path = target_path / ".rover"
    if not rover_file_path.exists():
        do_tour_recursion(target_path, operation_type, is_recursive, recursive_rel_path)
        return

    try:
        dir_mod_info = get_rover_dir_mod_info(target_path)
    except:
        do_tour_recursion(target_path, operation_type, is_recursive, recursive_rel_path)
        return
    remote_modified_files = getattr(dir_mod_info, "remote_modified_files")
    local_modified_files = getattr(dir_mod_info, "local_modified_files")
    local_deleted_files = getattr(dir_mod_info, "local_deleted_files")
    local_added_files = getattr(dir_mod_info, "local_added_files")

    local_altered_files = set(local_modified_files) | set(local_deleted_files) | set(local_added_files)
    union_altered_files = set(remote_modified_files) & set(local_altered_files)
    if len(union_altered_files) > 0:
        eprint(f"Tour: Modifications to remote and local files. '{target_path}'")
        eprint(f"Conflicting files: {union_altered_files}")
        sys.exit(1)

    remote_deleted_files = getattr(dir_mod_info, "remote_deleted_files")
    union_altered_deleted = set(local_altered_files) & set(remote_deleted_files)
    if len(union_altered_deleted) > 0:
        if set(union_altered_deleted) != set(local_deleted_files):
            print(f"Note: Remote deleted files have been deleted locally. '{target_path}'", file=sys.stderr)
            print(f"Conflicting files: {union_altered_deleted}", file=sys.stderr)

    remote_added_files = getattr(dir_mod_info, "remote_added_files")
    union_altered_added = set(local_altered_files) & set(remote_added_files)
    if len(union_altered_added) > 0:
        eprint(f"Tour: Remote added files that have been changed locally. '{target_path}'")
        eprint(f"Conflicting files: {union_altered_added}")
        sys.exit(1)

    if operation_type == TourOperationType_Status:
        if len(remote_modified_files) > 0:
            print(f"Remote modified files. ({recursive_rel_path})")
            for file in remote_modified_files:
                print(f"        {file}")

        if len(remote_added_files) > 0:
            print(f"Remote added files.    ({recursive_rel_path})")
            for file in remote_added_files:
                print(f"        {file}")

        if len(remote_deleted_files) > 0:
            print(f"Remote deleted files.  ({recursive_rel_path})")
            for file in remote_deleted_files:
                print(f"        {file}")
    else:
        if len(remote_modified_files) > 0:
            for file in remote_modified_files:
                file_to_view = target_path / file
                print(f"M {file_to_view}")

        if len(remote_added_files) > 0:
            for file in remote_added_files:
                file_to_view = target_path / file
                print(f"A {file_to_view}")

        if len(remote_deleted_files) > 0:
            for file in remote_deleted_files:
                file_to_view = target_path / file
                print(f"D {file_to_view}")

    do_tour_recursion(target_path, operation_type, is_recursive, recursive_rel_path)

def land_file(local_path):
    target_path = local_path.parent
    rover_file_path = target_path / ".rover"
    if not rover_file_path.exists():
        eprint(f"land_file: did not find rover file where land is being attempted. '{target_path}'")
        sys.exit(1)

    local_rover_file = read_rover_file(rover_file_path)
    url = getattr(local_rover_file, "url")
    parsed_url = urllib.parse.urlparse(url)

    if parsed_url.scheme not in supported_protocols.keys():
        eprint(f"Unable to land file: unsupported protocol '{parsed_url.scheme}'")
        sys.exit(1)

    # Special case for and abspath protocols. We have no guarantees of where
    # files are located when using full URLs.
    file_url = ""
    is_absolute_url = False
    file_url = urllib.parse.urljoin(url, local_path.name)
    found_file = False
    for file in getattr(local_rover_file, "files"):
        if FileEntry_get_filename_only(file) == local_path.name:
            found_file = True
            if getattr(file, "abs_path") != "0":
                # Do NOT use FileEntry_get_filename
                file_url = getattr(file, "filename")
                is_absolute_url = True
            break
    if not found_file and api_use_abspath(url):
        # Why this special case is needed: rover tour returns files that
        # have been added on the remote. It returns paths to local files
        # only. If a protocol uses absolute paths, then we can't reliably
        # reconstruct the URL from the URL in the .rover file and the
        # filename only.
        remote_rover_file = api_get_rover_file_from_url(url)
        for file in getattr(remote_rover_file, "files"):
            if FileEntry_get_filename_only(file) == local_path.name:
                file_url = getattr(file, "filename")
                is_absolute_url = True
                break
    # Unsupported protocols can appear inside of FileEntries. Refuse to land
    # the file in those cases.
    failed_land = False
    if parse_url(file_url).scheme not in supported_protocols.keys():
        eprint(f"Unsupported protocol specified in FileEntry: {file_url}")
        failed_land = True
    else:
        try:
            api_land_file(file_url, local_path)
        except RuntimeError as e:
            eprint(f"Failed to land url '{file_url}': {e}")
            failed_land = True

    file_entry = None
    ver = "0"
    remote_rover_file = api_get_rover_file_from_url(local_rover_file.url)
    ver = getattr(remote_rover_file, "ver")
    for file in remote_rover_file.files:
        if FileEntry_get_filename_only(file) == local_path.name:
            file_entry = file

    if file_entry is None:
        eprint(f"Failed to find remote file. {local_path.name}")
        eprint(f"{remote_rover_file}")
        raise RuntimeError(f"Failed to find remote file. {local_path.name}")

    # TODO Describe the purpose of "0" version. Need to spec this out better.
    if getattr(local_rover_file, 'ver') == "0":
        remote_file_entry = file_entry
        if not failed_land:
            file_contents = open(local_path, 'r', encoding='utf-8').read()
            sha = hashlib.sha256(file_contents.encode('utf-8')).hexdigest()
            stat = os.stat(local_path)
            mtime = int(os.path.getmtime(local_path))
            inode = stat.st_ino
        else:
            sha = empty_sha
            mtime = 0
            inode = 0
        abs_path = 1 if is_absolute_url else 0
        filename = file_url if is_absolute_url else local_path.name
        file_entry = FileEntry(
                sha,
                str(mtime),
                str(inode),
                abs_path,
                filename,
                getattr(remote_file_entry,"metadata"))

    files = []
    found_file = False
    for file in local_rover_file.files:
        if FileEntry_get_filename_only(file) == local_path.name:
            found_file = True
            files.append(file_entry)
        else:
            files.append(file)

    if found_file == False:
        files.append(file_entry)

    rover_file = RoverFile(
            getattr(local_rover_file, "url"),
            ver,
            files,
            getattr(local_rover_file, "directories"))

    write_rover_file(local_path.parent, rover_file)

def mark_for_tour(local_path):
    target_path = local_path.parent
    rover_file_path = target_path / ".rover"
    if not rover_file_path.exists():
        eprint(f"mark_for_tour: Rover file does not exist. '{rover_file_path}'")
        sys.exit(1)

    local_rover_file = read_rover_file(rover_file_path)

    files = []
    for file in local_rover_file.files:
        if FileEntry_get_filename_only(file) != local_path.name:
            files.append(file)

    rover_file = RoverFile(
            getattr(local_rover_file, "url"),
            getattr(local_rover_file, "ver"),
            files,
            getattr(local_rover_file, "directories"))

    write_rover_file(local_path.parent, rover_file)
    local_path.unlink()

def do_submit(target_path, is_recursive):
    rover_directory = target_path
    if target_path.is_file():
        rover_directory = target_path.parent
    elif not target_path.is_dir():
        eprint("do_submit: Only files and directories are supported.")
        sys.exit(1)

    rover_file_path = rover_directory / ".rover"
    if not rover_file_path.exists():
        eprint(f"do_submit: Submission must be in a directory that contains a rover file. '{rover_file_path}'")
        sys.exit(1)

    dir_mod_info = get_rover_dir_mod_info(rover_directory)
    remote_modified_files   = getattr(dir_mod_info, "remote_modified_files")
    remote_added_files      = getattr(dir_mod_info, "remote_added_files")
    remote_deleted_files    = getattr(dir_mod_info, "remote_deleted_files")
    local_modified_files    = getattr(dir_mod_info, "local_modified_files")
    local_deleted_files     = getattr(dir_mod_info, "local_deleted_files")
    local_added_files       = getattr(dir_mod_info, "local_added_files")

    # Ensure there will be no conflicts when uploading the content.
    remote_set = set(remote_modified_files) | set(remote_deleted_files) | set(remote_added_files)
    local_set = set(local_modified_files) | set(local_deleted_files) | set(local_added_files)

    # This is a restrictive test and includes cases we don't really care about
    # (such as both deleting the same file).
    conflict_set = remote_set & local_set
    if len(conflict_set) > 0:
        eprint("Submission failed due to conflicting changes on the remote.")
        eprint(f"Conflicting files: {conflict_set}")
        sys.exit(1)

    local_rover_file = read_rover_file(rover_file_path)
    local_file_dict = {}
    for file in local_rover_file.files:
        local_file_dict[FileEntry_get_filename_only(file)] = file

    if target_path.is_file():
        api_submit_file(getattr(local_rover_file, "url"), target_path)
        invalidate_caches()
        land_file(target_path)
    elif target_path.is_dir():
        # Submit local modifications
        for file in local_modified_files:
            api_submit_file(getattr(local_rover_file, "url"), target_path / file)

        for file in local_added_files:
            api_submit_file(getattr(local_rover_file, "url"), target_path / file)

        for file in local_deleted_files:
            api_delete_file(getattr(local_rover_file, "url"), local_rover_file)

        # Invalidate caches as we have modified the remote system and are expecting
        # the remote system to return the modifications.
        invalidate_caches()

        # Reland our modifications. Depending on protocol we may need to synchronize.
        for file in local_modified_files:
            land_file(target_path / Path(file))

        for file in local_added_files:
            land_file(target_path / Path(file))

        if is_recursive:
            for entry in target_path.iterdir():
                if entry.is_dir():
                    do_submit(entry, is_recursive)

def do_status(path, is_recursive, recursive_rel_path):
    rover_file_path = path / ".rover"
    if not rover_file_path.is_file():
        eprint(f"Unable to stat '{rover_file_path}'. No rover file exists.")
        sys.exit(1)

    recursive_path = ""
    if is_recursive:
        recursive_path = f" ({recursive_rel_path})"
    rover_file = read_rover_file(rover_file_path)
    files_changed_locally = get_modified_files(path, rover_file)
    if len(files_changed_locally) > 0:
        print(f"Modified files{recursive_path}:")
        for file in files_changed_locally:
            print(f"        {file}")
    remote_missing_files = get_deleted_files(path, rover_file)
    if len(remote_missing_files) > 0:
        print(f"Deleted files{recursive_path}:")
        for file in remote_missing_files:
            print(f"        {file}")
    locally_added_files = get_untracked_files(path, rover_file)
    if len(locally_added_files) > 0:
        print(f"Untracked files{recursive_path}:")
        for file in locally_added_files:
            print(f"        {file}")

    if is_recursive:
        for entry in path.iterdir():
            if entry.is_dir():
                if len(os.listdir(entry)) > 0:
                    do_status(entry, is_recursive, f"{recursive_rel_path}/{entry.name}")

def main():
    cli_args = sys.argv[1:]

    # We infer the 'status' sub-command if there are no arguments.
    if len(cli_args) == 0:
        cli_args.append("status")

    # We infer the 'land' sub-command if there are no subcommands and no hyphenated first argument.
    have_subcommands = False
    have_hyphenated_argument = 1 if cli_args[0].startswith("-") else 0
    for subcommand in subcommand_names:
        if subcommand in cli_args:
            have_subcommands = True
            break
    if not have_subcommands and not have_hyphenated_argument:
        cli_args.insert(0,"land")

    parser = argparse.ArgumentParser(description='A tool for interacting with versioned directories.')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose output')
    subparsers = parser.add_subparsers(help='')

    status_parser = subparsers.add_parser('status', help='Returns local status of rover directory.')
    status_parser.add_argument('path', nargs="?", help='Local path for which to take status.', default=".")
    status_parser.add_argument("--recursive", dest='recursive', action='store_true', help="Recursively take status.")
    status_parser.set_defaults(func=handle_status)

    land_parser = subparsers.add_parser('land', help='Lands a path or remote URL locally.')
    land_parser.add_argument('url_or_path', nargs=1, help='URL or filesystem path on which to operate.')
    land_parser.add_argument('target_path', nargs='?', help='Optional location to land into.')
    land_parser.add_argument("--recursive", dest='recursive', action='store_true', help="Recursively land.")
    land_parser.add_argument("--retour", dest='retour', action='store_true', help="Does not land any files. All files that would have landed will show up in 'rover tour'.")
    land_parser.add_argument("-u", "--leave-unread", dest='leave_unread', action='store_true', help="Does not land any files. All files are placed in an unread state and will not show up in rover tour until explictily added using 'rover fetch -u'")
    land_parser.set_defaults(func=handle_land)

    fetch_parser = subparsers.add_parser('fetch', help='Fetches individual files.')
    fetch_parser.add_argument('path', nargs='+', help='Path to file which should be fetch.')
    fetch_parser.add_argument('--retour', dest="retour", action='store_true', help="Deletes the file and ensures it will show up as part of 'rover tour'.")
    fetch_parser.add_argument('-u', '--retour-unread', dest="retour_unread", action='store_true', help="Takes one file that has been marked as 'unread' and places it back on 'rover tour'. ")
    fetch_parser.add_argument('stdin', nargs='?', type=argparse.FileType('r'), default=sys.stdin)
    fetch_parser.set_defaults(func=handle_fetch)

    tour_parser = subparsers.add_parser('tour', help='Think of this as a "remote" status. Returns added or modified remote files.')
    tour_parser.add_argument('path', nargs="?", help='Local path from which to start tour.', default=".")
    tour_parser.add_argument("--no-recursive", dest='no_recursive', action='store_true', help="Do not recursively execute the tour")
    tour_parser.add_argument("--status", dest="status", action='store_true', help="Prints status of files in tour to stdout.")
    tour_parser.set_defaults(func=handle_tour)

    submit_parser = subparsers.add_parser('submit', help='Submit changes to the remote. If applicable.')
    submit_parser.add_argument('path', nargs='?', help='Submit a local directory hierarchy to the remote.')
    submit_parser.add_argument("--recursive", dest='recursive', action='store_true', help="Recursively submit.")
    submit_parser.set_defaults(func=handle_submit)

    url_parser = subparsers.add_parser('url', help='Returns a URL given a local filesystem path.')
    url_parser.add_argument('path', nargs='+', help='Paths to convert to URLs.')
    url_parser.add_argument('--metadata', dest='metadata', action='store_true', help="Print metadata after URL")
    url_parser.set_defaults(func=handle_url)

    args = parser.parse_args(cli_args)

    if args.verbose and bool(args.verbose):
        global verbose
        verbose = True

    # Call subcommand that was indicated using set_defaults.
    args.func(args)

    sys.exit(0)

if __name__ == '__main__':
    main()
