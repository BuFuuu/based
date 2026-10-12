package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BuFuuu/based/internal/inspect"
	"github.com/BuFuuu/based/internal/model"
	"github.com/BuFuuu/based/internal/scan"
)

// Network lists every program that has a socket open right now: listening
// for connections, connected somewhere, or holding a raw socket. A program
// is a default when its file belongs to a package from Arch or Omarchy and
// is unchanged. Everything else is flagged, and so are signs of a reverse
// shell, whatever the program: a shell with a connection, input and output
// wired to a socket, or a network tool running a shell for the other side.
//
// It is a snapshot. A program that connects for a second every five
// minutes is only seen if the scan happens to catch it.
//
// Only the host's network namespace is read; containers' own sockets are
// not, but ports they publish show up as docker-proxy.
type Network struct {
	env   *scan.Env
	r     *scan.Reporter
	procs map[int]*netProc
	kids  map[int][]int // ppid -> pids
	mntNS string
	boot  time.Time

	total, flags int
}

func (*Network) ID() string                         { return "network" }
func (*Network) Title() string                      { return "Network" }
func (*Network) Estimate(_ *scan.Env, prev int) int { return prev }

type netSock struct {
	proto  string // tcp, udp, raw, packet (with a 6 for IPv6)
	state  string // listen, connected, connecting, bound
	local  netip.AddrPort
	remote netip.AddrPort
	uid    int
	inode  uint64
	owned  bool
}

type netProc struct {
	pid, ppid, uid int
	exe            string // as the kernel reports it, may end in " (deleted)"
	args           []string
	start          time.Time
	socks          []*netSock
	stdio          bool // fd 0, 1 or 2 is a network socket
}

var tcpStates = map[string]string{"01": "connected", "02": "connecting", "0A": "listen"}

func (c *Network) Collect(ctx context.Context, env *scan.Env, r *scan.Reporter) error {
	if env.Pacman == nil {
		return fmt.Errorf("package database not loaded")
	}
	c.env, c.r = env, r
	c.procs, c.kids = map[int]*netProc{}, map[int][]int{}
	c.mntNS, _ = os.Readlink("/proc/self/ns/mnt")
	c.boot = bootTime()

	socks := map[uint64]*netSock{}
	for _, t := range []string{"tcp", "tcp6", "udp", "udp6", "raw", "raw6"} {
		for _, s := range readSockTable("/proc/net/"+t, t) {
			socks[s.inode] = s
		}
	}
	for _, s := range readPacketTable("/proc/net/packet") {
		socks[s.inode] = s
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	c.matchProcs(socks)

	// one entry per program and kind of activity
	type group struct {
		mech  string
		prog  netProgram
		procs []*netProc
		socks []*netSock
	}
	groups := map[string]*group{}
	var order []string
	for _, pid := range sortedPids(c.procs) {
		p := c.procs[pid]
		if len(p.socks) == 0 || pid == os.Getpid() {
			continue
		}
		r.Tick(p.exe, "network")
		prog := c.program(p)
		for _, s := range p.socks {
			mech := mechanismOf(s)
			// the same interpreter can run harmless and odd code at once:
			// only processes judged alike share an entry
			key := mech + "\x00" + prog.path + "\x00" + prog.sandbox
			for _, fl := range prog.flags {
				key += "\x00" + fl.Code
			}
			g, ok := groups[key]
			if !ok {
				g = &group{mech: mech, prog: prog}
				groups[key] = g
				order = append(order, key)
			}
			if len(g.procs) == 0 || g.procs[len(g.procs)-1] != p {
				g.procs = append(g.procs, p)
			}
			g.socks = append(g.socks, s)
		}
	}
	for _, k := range order {
		g := groups[k]
		c.report(g.mech, g.prog, g.procs, g.socks)
	}
	c.hidden(socks)
	r.Note(fmt.Sprintf("%d programs · %d not default", c.total, c.flags))
	return nil
}

func mechanismOf(s *netSock) string {
	switch {
	case strings.HasPrefix(s.proto, "raw"), s.proto == "packet":
		return "raw sockets"
	case s.state == "listen", s.state == "bound":
		return "listening"
	}
	return "connections"
}

// ---- reading the kernel's tables -------------------------------------------

func readSockTable(path, proto string) []*netSock {
	var out []*netSock
	lines := readLines(path)
	for _, l := range lines[min(1, len(lines)):] {
		f := strings.Fields(l)
		if len(f) < 10 {
			continue
		}
		s := &netSock{proto: proto}
		s.local, _ = parseHexAddr(f[1])
		s.remote, _ = parseHexAddr(f[2])
		s.uid, _ = strconv.Atoi(f[7])
		s.inode, _ = strconv.ParseUint(f[9], 10, 64)
		if s.inode == 0 {
			continue // TIME_WAIT and friends: no program holds them any more
		}
		switch {
		case strings.HasPrefix(proto, "tcp"):
			s.state = tcpStates[f[3]]
		case strings.HasPrefix(proto, "udp"):
			if f[3] == "01" {
				s.state = "connected"
			} else if s.local.Port() != 0 {
				s.state = "bound"
			}
		default:
			s.state = "raw"
		}
		if s.state != "" {
			out = append(out, s)
		}
	}
	return out
}

// /proc/net/packet: sk RefCnt Type Proto Iface R Rmem User Inode
func readPacketTable(path string) []*netSock {
	var out []*netSock
	lines := readLines(path)
	for _, l := range lines[min(1, len(lines)):] {
		f := strings.Fields(l)
		if len(f) < 9 {
			continue
		}
		s := &netSock{proto: "packet", state: "raw"}
		s.uid, _ = strconv.Atoi(f[7])
		s.inode, _ = strconv.ParseUint(f[8], 10, 64)
		if s.inode != 0 {
			out = append(out, s)
		}
	}
	return out
}

// parseHexAddr decodes "0100007F:0035" (IPv4) or the 32-digit IPv6 form.
// The address is stored as 32-bit words in host (little-endian) order.
func parseHexAddr(v string) (netip.AddrPort, bool) {
	host, port, ok := strings.Cut(v, ":")
	if !ok || (len(host) != 8 && len(host) != 32) {
		return netip.AddrPort{}, false
	}
	b, err := hex.DecodeString(host)
	if err != nil {
		return netip.AddrPort{}, false
	}
	for i := 0; i+4 <= len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	a, _ := netip.AddrFromSlice(b)
	return netip.AddrPortFrom(a.Unmap(), uint16(p)), true
}

// matchProcs finds which process holds each socket, and records parents so
// shells started by a connected program can be found.
func (c *Network) matchProcs(socks map[uint64]*netSock) {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name()
		p := &netProc{pid: pid}
		p.ppid, p.start = c.procStat(dir)
		c.kids[p.ppid] = append(c.kids[p.ppid], pid)
		c.procs[pid] = p
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue // another user's process: needs root
		}
		for _, fd := range fds {
			link, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, _ := strconv.ParseUint(strings.TrimSuffix(link[8:], "]"), 10, 64)
			s, ok := socks[ino]
			if !ok {
				continue
			}
			if !containsSock(p.socks, s) { // forked children share sockets with their parent
				p.socks = append(p.socks, s)
			}
			s.owned = true
			if n, _ := strconv.Atoi(fd.Name()); n <= 2 && s.proto != "packet" && !strings.HasPrefix(s.proto, "raw") {
				p.stdio = true
			}
		}
		if len(p.socks) > 0 {
			p.exe, _ = os.Readlink(dir + "/exe")
			p.args = strings.Split(strings.TrimRight(string(readFileSmall(dir+"/cmdline")), "\x00"), "\x00")
			if info, err := os.Stat(dir); err == nil {
				p.uid = int(info.Sys().(*syscall.Stat_t).Uid)
			}
		}
	}
}

func containsSock(list []*netSock, s *netSock) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// procStat returns the parent pid and the start time from /proc/<pid>/stat.
func (c *Network) procStat(dir string) (int, time.Time) {
	b := readFileSmall(dir + "/stat")
	i := strings.LastIndexByte(string(b), ')') // the name may contain spaces
	if i < 0 {
		return 0, time.Time{}
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0, time.Time{}
	}
	ppid, _ := strconv.Atoi(f[1])
	ticks, _ := strconv.ParseInt(f[19], 10, 64)
	if c.boot.IsZero() {
		return ppid, time.Time{}
	}
	return ppid, c.boot.Add(time.Duration(ticks) * time.Second / 100) // USER_HZ is 100 on Linux
}

func bootTime() time.Time {
	for _, l := range readLines("/proc/stat") {
		if v, ok := strings.CutPrefix(l, "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
				return time.Unix(n, 0)
			}
		}
	}
	return time.Time{}
}

func sortedPids(m map[int]*netProc) []int {
	out := make([]int, 0, len(m))
	for pid := range m {
		out = append(out, pid)
	}
	sort.Ints(out)
	return out
}

// ---- judging the program -----------------------------------------------------

// netProgram is the file that decides whether a process is trusted: its
// executable, or the script an interpreter runs.
type netProgram struct {
	path    string
	name    string
	sandbox string // "flatpak <app>" or "container"
	trust   model.Trust
	why     string // where it comes from
	flags   []model.Flag
	kind    string // "shell", "tool", "interpreter" or ""
}

var (
	shellNames  = map[string]bool{"sh": true, "bash": true, "zsh": true, "fish": true, "dash": true, "ksh": true, "ash": true, "busybox": true, "nu": true}
	netTools    = map[string]bool{"nc": true, "ncat": true, "netcat": true, "socat": true, "telnet": true}
	interpreter = regexp.MustCompile(`^(python[0-9.]*|node|nodejs|ruby|perl[0-9.]*|php[0-9.]*|bun|deno|lua[0-9.]*|luajit|java)$`)
)

func (c *Network) program(p *netProc) netProgram {
	exe := p.exe
	deleted := strings.HasSuffix(exe, " (deleted)")
	exe = strings.TrimSuffix(exe, " (deleted)")
	prog := netProgram{path: exe, name: filepath.Base(exe)}
	if exe == "" {
		prog.path, prog.name = "/proc/"+strconv.Itoa(p.pid), "pid "+strconv.Itoa(p.pid)
		return prog
	}
	if strings.HasPrefix(prog.name, "memfd:") {
		prog.flags = append(prog.flags, model.FlagNetMemory)
		return prog
	}

	// Is the path the program sees the same file as on this system? Not in
	// a sandbox or container, and not after the file was replaced.
	running, err1 := os.Stat("/proc/" + strconv.Itoa(p.pid) + "/exe")
	onDisk, err2 := os.Stat(exe)
	same := err1 == nil && err2 == nil && os.SameFile(running, onDisk)
	if !same {
		ns, _ := os.Readlink("/proc/" + strconv.Itoa(p.pid) + "/ns/mnt")
		switch {
		case ns != "" && ns != c.mntNS:
			prog.sandbox = "container"
			if app := flatpakApp(p.pid); app != "" {
				prog.sandbox, prog.name = "flatpak "+app, app
			}
			prog.why = "runs in a " + prog.sandbox
			prog.flags = append(prog.flags, model.FlagNetSandbox)
			return prog
		case deleted && err2 == nil && c.env.Pacman.Owner(exe) != nil:
			prog.why = "updated on disk since it started; restart it to run the new version"
		case deleted || err2 != nil:
			prog.flags = append(prog.flags, model.FlagNetDeleted)
		}
	}
	for _, t := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(exe, t) {
			prog.flags = append(prog.flags, model.FlagExecInTemp)
		}
	}

	base := filepath.Base(exe)
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		base = filepath.Base(real)
	}
	switch {
	case shellNames[base]:
		prog.kind = "shell"
	case netTools[base]:
		prog.kind = "tool"
	case interpreter.MatchString(base):
		prog.kind = "interpreter"
	}

	owner := c.env.Pacman.Owner(exe)
	if prog.kind == "interpreter" {
		script, inline := scriptOf(p, base)
		switch {
		case inline:
			prog.flags = append(prog.flags, model.FlagNetInline)
		case script != "":
			prog.path, prog.name = script, filepath.Base(script)
			owner = c.env.Pacman.Owner(script)
			if owner == nil {
				prog.flags = append(prog.flags, model.FlagNetScript)
				prog.why = "run by " + base
				return prog
			}
		}
	}

	switch {
	case owner == nil:
		prog.flags = append(prog.flags, model.FlagNetUnowned)
	default:
		prog.trust = c.env.Trust(owner)
		if prog.why == "" {
			prog.why = "from package " + owner.Name + " (" + prog.trust.Label() + ")"
		}
		if prog.trust == model.TrustForeign {
			prog.flags = append(prog.flags, model.FlagNetForeign)
		}
		if !packageFileUnchanged(c.env, prog.path) {
			prog.flags = append(prog.flags, model.FlagModified)
		}
	}
	return prog
}

func flatpakApp(pid int) string {
	for _, l := range readLines("/proc/" + strconv.Itoa(pid) + "/root/.flatpak-info") {
		if v, ok := strings.CutPrefix(l, "name="); ok {
			return v
		}
	}
	return ""
}

// scriptOf finds the file an interpreter runs. inline is true when the code
// is not in a file: given with -c/-e, piped in, or typed at a prompt.
func scriptOf(p *netProc, interp string) (script string, inline bool) {
	inlineOpts := map[string]bool{"-c": true, "-e": true, "-E": true, "--eval": true, "-p": true, "--print": true, "-r": true}
	valueOpts := map[string]bool{"-W": true, "-X": true, "-Q": true, "--require": true, "--import": true, "--loader": true,
		"-I": true, "-cp": true, "-classpath": true}
	if strings.HasPrefix(interp, "node") || interp == "bun" || interp == "deno" {
		valueOpts["-r"], inlineOpts["-r"] = true, false
	}
	cwd, _ := os.Readlink("/proc/" + strconv.Itoa(p.pid) + "/cwd")
	resolve := func(a string) string {
		if !filepath.IsAbs(a) {
			a = filepath.Join(cwd, a)
		}
		if info, err := os.Stat(a); err == nil && info.Mode().IsRegular() {
			return a
		}
		return ""
	}
	args := p.args[min(1, len(p.args)):]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case inlineOpts[a]:
			return "", true
		case a == "-m" && i+1 < len(args): // python module: from the working directory, or the interpreter's own
			mod := strings.ReplaceAll(args[i+1], ".", "/")
			for _, cand := range []string{mod + ".py", mod + "/__main__.py"} {
				if s := resolve(cand); s != "" {
					return s, false
				}
			}
			return "", false
		case a == "-jar" && i+1 < len(args):
			return resolve(args[i+1]), false
		case valueOpts[a]:
			i++
		case strings.HasPrefix(a, "-"):
		default:
			if s := resolve(a); s != "" {
				return s, false
			}
			// a subcommand like "bun run": keep looking
		}
	}
	return "", true
}

// interactiveShell reports whether pid is a shell that reads its commands
// from its input, as a reverse shell does. Shells that run one command
// (bash -c ..., as editors and AI agents use them) or a script do not.
func interactiveShell(pid int) bool {
	return interactiveShellArgs(strings.Split(strings.TrimRight(string(readFileSmall("/proc/"+strconv.Itoa(pid)+"/cmdline")), "\x00"), "\x00"))
}

func interactiveShellArgs(args []string) bool {
	if len(args) == 0 || !shellNames[strings.TrimPrefix(filepath.Base(args[0]), "-")] {
		return false
	}
	for _, a := range args[1:] {
		switch {
		case a == "-i" || a == "--interactive":
			return true
		case a == "--" || !strings.HasPrefix(a, "-"):
			return false // a script
		case !strings.HasPrefix(a, "--") && strings.Contains(a, "c"):
			return false // -c, -lc: one command
		}
	}
	return true
}

// ---- reporting -------------------------------------------------------------

func (c *Network) report(mech string, prog netProgram, procs []*netProc, socks []*netSock) {
	c.total++
	flags := append([]model.Flag(nil), prog.flags...)
	inet := false
	for _, s := range socks {
		if s.proto != "packet" && !strings.HasPrefix(s.proto, "raw") {
			inet = true
		}
	}
	trusted := len(flags) == 0
	if prog.kind == "shell" && inet {
		flags = append(flags, model.FlagNetShell)
	}
	if prog.kind == "tool" && inet {
		flags = append(flags, model.FlagNetTool)
	}
	root := false
	for _, p := range procs {
		if p.stdio && inet && (!trusted || prog.kind != "") { // inetd-style daemons get their socket as stdin
			flags = append(flags, model.FlagNetStdio)
		}
		if p.uid == 0 {
			root = true
		}
		// a connected program that starts shells is how most reverse
		// shells look; sshd and the like are trusted and exempt
		if mech == "connections" && (!trusted || prog.kind != "") {
			for _, kid := range c.kids[p.pid] {
				if interactiveShell(kid) {
					flags = append(flags, model.FlagNetShellChild)
					break
				}
			}
		}
	}
	if mech == "raw sockets" && len(flags) > 0 {
		flags = append(flags, model.FlagNetRaw)
	}

	e := model.Entry{Mechanism: mech, Name: prog.name, Path: prog.path, Runs: describeSocks(mech, socks), Why: prog.why}
	if prog.sandbox != "" {
		e.Name += " (" + prog.sandbox + ")"
	}
	if len(flags) == 0 {
		e.State = "default"
		if e.Why == "" {
			e.Why = "default"
		}
		c.r.NetEntry(e, nil)
		return
	}

	// what it can reach makes it more or less serious, but only once
	// something about the program is already odd
	switch mech {
	case "listening":
		public := false
		for _, s := range socks {
			if !s.local.Addr().IsLoopback() {
				public = true
			}
		}
		if public {
			flags = append(flags, model.FlagNetListen)
		} else {
			flags = append(flags, model.FlagNetListenLocal)
		}
	case "connections":
		flags = append(flags, model.FlagNetOut)
	}
	if root {
		flags = append(flags, model.FlagRunsAsRoot)
	}

	c.flags++
	e.State = "flagged"
	e.Why = flags[0].Label
	f := model.Finding{
		Kind:    model.KindNetwork,
		ID:      model.MakeID(model.KindNetwork, mech+"\x00"+prog.path+"\x00"+prog.sandbox),
		Subject: prog.path,
		Title:   mech + ": " + e.Name,
		Trust:   prog.trust,
	}
	for _, p := range procs {
		if f.Added.IsZero() || (!p.start.IsZero() && p.start.Before(f.Added)) {
			f.Added = p.start
		}
	}
	f.AddedSource = "program started"
	for _, fl := range flags {
		f.AddFlag(fl)
	}
	var pids []string
	for _, p := range procs {
		pids = append(pids, strconv.Itoa(p.pid))
	}
	p0 := procs[0]
	f.SetFact("mechanism", mech)
	f.SetFact("program", strings.TrimSuffix(p0.exe, " (deleted)"))
	f.SetFact("command", TruncateMiddle(strings.Join(p0.args, " "), 300))
	f.SetFact("pids", strings.Join(pids, ", "))
	f.SetFact("user", userName(p0.uid))
	f.SetFact("sockets", e.Runs)
	f.SetFact("where from", prog.why)
	f.SetFact("sandbox", prog.sandbox)
	var lines []string
	for _, p := range procs {
		lines = append(lines, fmt.Sprintf("pid %d: %s", p.pid, strings.Join(p.args, " ")))
	}
	for _, s := range socks {
		lines = append(lines, "  "+sockLine(s))
	}
	f.Preview = strings.Join(lines[:min(len(lines), 40)], "\n")

	// an accept covers this program doing this kind of thing; it is voided
	// when the program file changes, it gains a warning sign, or (for a
	// listener) it opens other ports
	fp := programHash(prog.path)
	for _, fl := range f.Flags {
		fp += "\x00" + fl.Code
	}
	if mech == "listening" {
		fp += "\x00" + e.Runs
	}
	sum := sha256.Sum256([]byte(fp))
	f.Fingerprint = hex.EncodeToString(sum[:8])
	c.r.NetEntry(e, &f)
}

// hidden lists sockets whose program could not be seen (another user's,
// without root).
func (c *Network) hidden(socks map[uint64]*netSock) {
	listen := map[string][]*netSock{} // "port user"
	var ports []string
	conns, raw := 0, 0
	for _, s := range socks {
		if s.owned {
			continue
		}
		switch mechanismOf(s) {
		case "listening":
			k := fmt.Sprintf("%05d %s", s.local.Port(), userName(s.uid))
			if listen[k] == nil {
				ports = append(ports, k)
			}
			listen[k] = append(listen[k], s)
		case "connections":
			conns++
		default:
			raw++
		}
	}
	sort.Strings(ports)
	why := "program hidden: run `based scan --sudo`"
	for _, k := range ports {
		port, user, _ := strings.Cut(k, " ")
		port = strings.TrimLeft(port, "0")
		c.r.NetEntry(model.Entry{Mechanism: "listening", Name: "port " + port + " (" + user + ")",
			Runs: describeSocks("listening", listen[k]), State: "unreadable", Why: why}, nil)
	}
	if conns > 0 {
		c.r.NetEntry(model.Entry{Mechanism: "connections", Name: plural(conns, "connection"),
			Runs: "of programs Based can't see", State: "unreadable", Why: why}, nil)
	}
	if raw > 0 {
		c.r.NetEntry(model.Entry{Mechanism: "raw sockets", Name: plural(raw, "raw socket"),
			Runs: "of programs Based can't see", State: "unreadable", Why: why}, nil)
	}
}

func describeSocks(mech string, socks []*netSock) string {
	seen := map[string]bool{}
	var parts []string
	for _, s := range socks {
		var p string
		switch mech {
		case "listening":
			p = strings.TrimSuffix(s.proto, "6") + " " + addrString(s.local)
		case "connections":
			p = addrString(s.remote) + " (" + place(s.remote.Addr()) + ")"
		default:
			p = s.proto
		}
		if !seen[p] {
			seen[p] = true
			parts = append(parts, p)
		}
	}
	sort.Strings(parts)
	more := ""
	if len(parts) > 4 {
		more = fmt.Sprintf(" +%d more", len(parts)-4)
		parts = parts[:4]
	}
	out := strings.Join(parts, ", ") + more
	if mech == "connections" {
		out = fmt.Sprintf("%d to ", len(socks)) + out
	}
	return out
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return strconv.Itoa(n) + " " + what + "s"
}

func sockLine(s *netSock) string {
	switch s.state {
	case "listen", "bound":
		return s.proto + " listening on " + addrString(s.local) + " (" + reach(s.local.Addr()) + ")"
	case "raw":
		return s.proto + " socket"
	}
	return s.proto + " " + s.state + " " + addrString(s.local) + " → " + addrString(s.remote) + " (" + place(s.remote.Addr()) + ")"
}

func addrString(a netip.AddrPort) string {
	if a.Addr().IsUnspecified() {
		return "*:" + strconv.Itoa(int(a.Port()))
	}
	return a.String()
}

// reach says who can connect to a listening address.
func reach(a netip.Addr) string {
	if a.IsLoopback() {
		return "this computer only"
	}
	return "other computers"
}

// place says where a remote address is, without looking anything up.
func place(a netip.Addr) string {
	switch {
	case a.IsLoopback():
		return "this computer"
	case a.IsPrivate(), a.IsLinkLocalUnicast(), a.IsMulticast():
		return "local network"
	}
	return "internet"
}

func programHash(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return path
	}
	if info.Size() < 128<<20 {
		if h, err := inspect.SHA256(path); err == nil {
			return h
		}
	}
	return strconv.FormatInt(info.Size(), 10) + ":" + strconv.FormatInt(info.ModTime().UnixNano(), 10)
}

func userName(uid int) string {
	for _, l := range readLines("/etc/passwd") {
		f := strings.Split(l, ":")
		if len(f) > 2 && f[2] == strconv.Itoa(uid) {
			return f[0]
		}
	}
	return "uid " + strconv.Itoa(uid)
}

// TruncateMiddle shortens s to n characters, keeping both ends.
func TruncateMiddle(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n/2-1] + "…" + s[len(s)-n/2+1:]
}
