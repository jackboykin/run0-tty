# run0-tty

run0 that asks for your password in the terminal, not in a desktop popup:

```
$ run0 true
password:
$
```

run0-tty registers its own agent for its process, then runs the real run0 in that same process. polkit asks run0-tty's agent, and the agent asks on the terminal.

The process keeps its parent, your shell, so polkit still remembers you between calls from the same terminal.

## Install

The package provides `run0-tty` and a `run0` link to it. Put it before systemd's `run0` in `PATH`:

```nix
inputs.run0-tty = {
  url = "github:jackboykin/run0-tty";
  inputs.nixpkgs.follows = "nixpkgs";
};

nixpkgs.overlays = [inputs.run0-tty.overlays.default];
users.users.YOU.packages = [pkgs.run0-tty];
```

`YOU` is your username. run0-tty requires polkit 124 or later and systemd 256 or later.

## Behavior

- You get one try. A wrong password fails the command.
- Ctrl-C or Ctrl-D at the prompt cancels.
- polkit remembers you only in a terminal emulator, not on a virtual console.
