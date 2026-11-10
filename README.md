# run0-tty

A terminal polkit agent for run0, systemctl and the other systemd tools. It asks in the terminal, not in a desktop popup, with one quiet line:

```
$ run0 true
password:
$ systemctl restart nginx
restart 'nginx.service'
password:
$
```

systemd tools start the first `pkttyagent` in `PATH` to answer their polkit queries. run0-tty installs itself under that name, in place of polkit's own, and answers even when a desktop's agent is running.

polkit still remembers you between calls from the same terminal.

## Install

Put the package before polkit's `pkttyagent` in `PATH`:

```nix
inputs.run0-tty = {
  url = "github:jackboykin/run0-tty";
  inputs.nixpkgs.follows = "nixpkgs";
};

nixpkgs.overlays = [inputs.run0-tty.overlays.default];
users.users.YOU.packages = [pkgs.run0-tty];
```

`YOU` is your username. run0-tty requires polkit 124 or later and systemd 260 or later.

## Behavior

- You get one try. A wrong password fails the command.
- Ctrl-C or Ctrl-D at the prompt cancels.
- The line above the prompt is polkit's reason for asking. run0 and systemd-run show none.
- polkit remembers you only in a terminal emulator, not on a virtual console.
