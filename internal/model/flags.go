package model

// The flag catalogue. Weights are summed (capped at 100) and mapped to a
// severity by SeverityFor: >=70 high, >=40 med, >=15 low, otherwise info.
// Based is not an antivirus: what a file contains (risky-looking patterns)
// only nudges the score; where it comes from and how much that source can be
// trusted decides it. Places matter: /etc and /var should hold only settings and data that
// packages put there, so strays weigh more; /tmp and home are expected to
// hold your own files and weigh less.
var (
	FlagUnownedSystem    = Flag{"unowned", "not owned by any package", 15}
	FlagUnownedBinary    = Flag{"unowned-bin", "unowned executable in a system path", 45}
	FlagUnownedLibrary   = Flag{"unowned-lib", "unowned shared library", 40}
	FlagUnownedVar       = Flag{"unowned-var", "runtime data not owned by any package", 0}
	FlagExecInVar        = Flag{"exec-var", "a program inside /var, where data belongs", 45}
	FlagUnownedEtc       = Flag{"unowned-etc", "in /etc, but no package or Omarchy put it there", 25}
	FlagEtcProgram       = Flag{"etc-program", "a program in /etc, where only settings belong", 40}
	FlagModified         = Flag{"modified", "content differs from its package", 80}
	FlagConfigEdited     = Flag{"config-edited", "config differs from the package default", 0}
	FlagModeChanged      = Flag{"mode-changed", "permissions differ from its package", 40}
	FlagSUID             = Flag{"suid", "setuid bit set", 50}
	FlagSGID             = Flag{"sgid", "setgid bit set", 35}
	FlagCapabilities     = Flag{"caps", "has file capabilities", 40}
	FlagWorldWritable    = Flag{"world-writable", "world-writable in a system path", 30}
	FlagExecInTemp       = Flag{"exec-temp", "executable in a temp directory", 35}
	FlagHidden           = Flag{"hidden", "hidden name or inside a hidden directory", 15}
	FlagELF              = Flag{"elf", "compiled binary (ELF)", 10}
	FlagStatic           = Flag{"static", "statically linked binary", 15}
	FlagPacked           = Flag{"packed", "packed with UPX", 20}
	FlagUnknownOwner     = Flag{"no-owner", "owned by a uid with no user", 30}
	FlagExecutable       = Flag{"exec", "executable", 5}
	FlagSuspiciousScript = Flag{"sus-script", "script contains risky patterns", 10}
	FlagExtraConfig      = Flag{"extra-config", "not part of the Omarchy defaults", 0}
	FlagEditedConfig     = Flag{"edited-config", "differs from the Omarchy default", 0}
	FlagExtraPackage     = Flag{"extra-pkg", "not part of the Omarchy install", 0}
	FlagForeignPackage   = Flag{"foreign-pkg", "not from Arch or Omarchy (AUR, manual or third-party repo)", 20}
	FlagInstallScript    = Flag{"install-script", "package install script has risky patterns", 10}
	FlagReplacedLink     = Flag{"replaced-link", "a package file was replaced by a link, or a link points elsewhere", 70}
	FlagOwnerChanged     = Flag{"owner-changed", "now owned by a normal user, who can change it", 45}
	FlagRootCaps         = Flag{"root-caps", "capabilities that amount to root (setuid, sys_admin, ...)", 60}
	FlagKernelModule     = Flag{"kmod", "kernel module no package owns: it runs inside the kernel", 45}
	FlagDKMS             = Flag{"dkms", "built by DKMS from source a package installed", -30}
	FlagSecurityConfig   = Flag{"security-config", "controls logins, sudo or how programs load", 25}

	// persistence
	FlagAutostart    = Flag{"autostart", "starts automatically, not set up by Omarchy or a package", 20}
	FlagLocalUnit    = Flag{"local-unit", "defined locally, not shipped by a package", 15}
	FlagRunsAsRoot   = Flag{"as-root", "runs as root", 15}
	FlagRunsFromOdd  = Flag{"odd-exec", "runs a program from home, /tmp or /opt, or one no package owns", 25}
	FlagChangedFile  = Flag{"changed", "differs from what its package shipped", 30}
	FlagAddedLines   = Flag{"added-lines", "has lines Omarchy's default doesn't", 15}
	FlagPreload      = Flag{"preload", "/etc/ld.so.preload injects a library into every program", 80}
	FlagSSHKeys      = Flag{"ssh-keys", "allows SSH login with a key", 30}
	FlagSudoers      = Flag{"sudoers", "changes who may use sudo", 25}
	FlagNoPasswd     = Flag{"nopasswd", "grants sudo without a password", 20}
	FlagAgentHook    = Flag{"agent-hook", "AI agent runs this command automatically", 20}
	FlagAgentTool    = Flag{"agent-tool", "AI agent can start this tool server", 10}
	FlagShellPlugin  = Flag{"shell-plugin", "third-party code running inside the Omarchy shell", 15}
	FlagGitHooksPath = Flag{"git-hooks", "global git hooks run on every repository", 25}
	FlagRepoHook     = Flag{"repo-hook", "runs on git commands in this repository", 15}
	FlagLauncher     = Flag{"launcher", "replaces the launcher of an installed app", 30}
	FlagPythonHook   = Flag{"python-hook", "runs code every time Python starts", 35}
	FlagDBusService  = Flag{"dbus", "a program starts it on demand over D-Bus", 20}
	FlagRootAccount  = Flag{"root-uid", "another account with root's user id 0", 80}
	FlagExtraLogin   = Flag{"extra-login", "another account that can log in", 20}
	FlagExtraAdmin   = Flag{"extra-admin", "another account that may use sudo", 30}
	FlagNoPassword   = Flag{"empty-password", "can log in without a password", 50}

	// network
	FlagNetListen      = Flag{"net-listen", "accepts connections from other computers", 20}
	FlagNetListenLocal = Flag{"net-listen-local", "accepts connections from this computer only", 5}
	FlagNetOut         = Flag{"net-out", "has open connections", 5}
	FlagNetUnowned     = Flag{"net-unowned", "program not owned by any package", 30}
	FlagNetForeign     = Flag{"net-foreign", "program from the AUR or a third-party repo", 15}
	FlagNetScript      = Flag{"net-script", "an interpreter running code no package owns", 30}
	FlagNetInline      = Flag{"net-inline", "an interpreter running code that is not in a file (typed or piped in)", 40}
	FlagNetShell       = Flag{"net-shell", "a shell holds a network connection", 60}
	FlagNetStdio       = Flag{"net-stdio", "its input and output go straight to the network (reverse shell sign)", 70}
	FlagNetShellChild  = Flag{"net-shell-child", "runs a shell for the other side (reverse shell sign)", 50}
	FlagNetTool        = Flag{"net-tool", "a raw network tool (nc, socat) holds the connection", 40}
	FlagNetDeleted     = Flag{"net-deleted", "its program file was deleted while it runs", 50}
	FlagNetMemory      = Flag{"net-memfd", "runs from memory only, no file on disk", 70}
	FlagNetRaw         = Flag{"net-raw", "raw socket: can see or forge any traffic", 30}
	FlagNetSandbox     = Flag{"net-sandbox", "runs in a sandbox or container, its files can't be checked", 15}
)
