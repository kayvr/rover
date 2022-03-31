# Rover

Rover is an experimental CLI interface for directory-based subscription. It behaves similarly to git and works with local filesystems and gemini.

You'll find an overview of this utility on gemini.

1) gemini://kayvr.com/gemlog/2022-03-17-Rover-Experiments.gmi
2) gemini://kayvr.com/gemlog/2022-03-31-Rover-Tours-With-Gemini.gmi

## Installation

Rover requires only Python 3.6. To use rover, clone this directory and run rover.py. To install, symlink rover.py so it shows up as 'rover' in your PATH.

## Usage

```
$ mkdir rover
$ cd rover
$ rover land ~/oss/rover-source
$ rover land gemini://kayvr.com/gemlog/index.gmi kayvr
```

This creates the following tree.

```
.
├── kayvr
│   ├── 2022-01-22-Hi-Gemini.gmi
│   ├── ...
│   ├── 2022-03-17-Rover-Experiments.gmi
│   ├── feed.xml
│   ├── index.gmi
│   └── .rover
└── rover-source
    ├── .gitignore
    ├── gemini
    ├── README.md
    ├── .rover
    └── rover.py
```

It is recommended to use the -u parameter when landing directories or URLs. This marks all files as unread. Unread files can be seen using `rover status`, added to a tour using `rover fetch . -u`, or grabbed individually using `rover fetch <filename>`.

```
$ rover land -u gemini://kayvr.com/gemlog/index.gmi kayvr
```

## Local Filesystem

Rover operates on local filesystems by allowing you to 'subscribe' to directory updates. Using rover you'll know if anyone, yourself included, modifies the contents of a directory. Want to subscribe to updates from another user on a pubnix? Or simply keep track of changes you're making to a git repos and directories? Rover'll do that.

You can find an overview of using rover for a local filesystem here:

* gemini://kayvr.com/gemlog/2022-03-17-Rover-Experiments.gmi

### Important notes

In order to land a directory the path must be absolute. As in: `rover land ~/dir` not `rover land ./dir`.

Relative paths are allowed in one circumstance: If you are in a directory that was landed with rover then you may use relative paths. For example:

```
$ rover land ~/foo bar
$ cd bar
$ rover land a # If ~/foo/a exists
```

## Gemini

Rover also supports gemini. Using rover with gemin is similar to local filesystems. Though rover treats gemtext files (like index.gmi) as directories. For more info, check out:

* gemini://kayvr.com/gemlog/2022-03-31-Rover-Tours-With-Gemini.gmi

