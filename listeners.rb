#!/usr/bin/env ruby
# Copyright 2023 Mike Carlton
# Released under terms of the MIT License:
#   http://www.opensource.org/licenses/mit-license.php

require 'etc'
require 'ipaddr'

UDPv4 = "/proc/net/udp"
UDPv6 = "/proc/net/udp6"
TCPv4 = "/proc/net/tcp"
TCPv6 = "/proc/net/tcp6"

Family = Struct.new(:files, :listen_state, :enabled, keyword_init: true)
Listener = Struct.new(:address, :uid, :inode, keyword_init: true)
ProcessInfo = Struct.new(:user, :cmd, :addresses, keyword_init: true)

# adds entry to listeners if the socket is in listening state
# https://www.kernel.org/doc/html/v5.8/networking/proc_net_tcp.html
def collect(entry, listeners, listen_state)
  local_address, st, uid, inode = entry.split.values_at(1, 3, 7, 9)

  if st == listen_state
    address_str, port_str = local_address.split(':')
    port = Integer("0x#{port_str}")
    listeners[port] ||= [ ]     # an array of listeners per port (e.g. v4 and v6)

    words = address_str.length / 8    # ipv4: 1 word, ipv6: 4 words
    address = IPAddr.new_ntoh([address_str].pack('H*').           # hex string to string of bytes
                                            unpack("N#{words}").  # 32 bits at a time in network order to integer
                                            pack("L#{words}"))    # back to little endian
    listeners[port] << Listener.new(address: address, uid: Integer(uid), inode: Integer(inode))
  end
end

# return username for user id
def user(uid)
  Etc.getpwuid(uid).name
rescue ArgumentError
  "----"
end

# return process name for process id
def process(pid, extended: false)
  path = "/proc/#{pid}/cmdline"
  if File.exist?(path)
    words = File.read(path).split(/\0/)
    extended ? words.join(' ') : words.first
  end
end

def root?
  Etc.getpwuid.uid == 0
end

families = {
  udp: Family.new(files: [ UDPv4, UDPv6 ], listen_state: '07', enabled: true),
  tcp: Family.new(files: [ TCPv4, TCPv6 ], listen_state: '0A', enabled: true),
}
single_port = nil
single_user = nil
single_pid = nil
quiet = false
extended = false

USAGE = "Usage: #{$0} [-h] [-q] [-x] [-4] [-6] [-u] [-t] [PORT_NUMBER | USERNAME | ^PID]"
ARGV.each do |arg|
  case arg
  when '-4' then families[:tcp].files = [ TCPv4 ]; families[:udp].files = [ UDPv4 ]
  when '-6' then families[:tcp].files = [ TCPv6 ]; families[:udp].files = [ UDPv6 ]
  when '-t' then families[:tcp].enabled = true; families[:udp].enabled = false
  when '-u' then families[:udp].enabled = true; families[:tcp].enabled = false
  when '-q' then quiet = true
  when '-x' then extended = true
  when /^\d+$/ then single_port = Integer(arg)
  when /^[a-z][-a-z]*$/ then single_user = arg
  when /^\^\d+$/ then single_pid = Integer(arg[1..])
  when '-h'
    puts <<~EOS
    #{USAGE}
      -4: show only IPv4 listeners
      -6: show only IPv6 listeners
      -u: show only UDP listeners
      -t: show only TCP listeners
      -q: no output, exit status only
      -x: show extended process info (requires root access)
      -h: show this help
      PORT_NUMBER: show only listeners for PORT
      USERNAME: show only processes owned by USERNAME
      ^PID: show only listeners owned by process PID (requires root access)
    Exits with status 0 (success) if any listeners found, else exits with status 1
    EOS
    exit(0)
  else
    STDERR.puts USAGE
    exit(1)
  end
end

if (extended || single_pid) && !root?
  STDERR.puts "Showing process info or filtering on PID requires root access"
  exit(1)
end

# map inodes to pids by scanning /proc/*/fd (requires root)
inode_to_pid = { }
if root?
  sock_re = /socket:\[(\d+)\]/
  path_re = %r{^/proc/(\d+)/}
  Dir.glob("/proc/[0-9]*/fd/*") do |path|
    begin
      if sock_re.match(File.readlink(path))
        inode = Integer(Regexp.last_match[1])
        pid = Integer(path_re.match(path)[1])
        inode_to_pid[inode] = pid
      end
    rescue Errno::ENOENT
      # ignore it
    end
  end
end

matched = false
stanza = 0
families.each do |name, family|
  next unless family.enabled

  listeners = { }
  lines = [ ]
  family.files.each do |file|
    begin
      # skip the header line
      File.read(file).lines[1..].each { |entry| collect(entry, listeners, family.listen_state) }
    rescue StandardError => e
      STDERR.puts "Unable to read socket file '#{file}': #{e}"
      exit(1)
    end

    header = [ name.upcase, "ADDR", "USER" ]
    header.concat([ "PID", "CMD" ]) if root?
    lines = [ header ]

    listeners.keys.sort.each do |port|
      processes = { }
      listeners[port].sort_by { |listener| listener.address.family }.each do |listener|
        pid = inode_to_pid[listener.inode]
        processes[pid] ||= ProcessInfo.new(user: user(listener.uid), cmd: pid && process(pid, extended: extended), addresses: [ ])
        processes[pid].addresses << listener.address
      end

      processes.each do |pid, process|
        if single_port && port == single_port ||
           single_user && process.user == single_user ||
           single_pid && pid == single_pid ||
           !(single_port || single_user || single_pid)
          line = [ port, process.addresses.join(', '), process.user ]
          line.concat([ pid, process.cmd ]) if root?
          lines << line
          matched = true
        end
      end
    end
  end

  unless quiet || lines.size == 1
    puts if stanza > 0

    # find max width of each column
    widths = Array.new(lines.first.length, 0)
    lines.each { |line| line.each.with_index { |field, i| widths[i] = [widths[i], field.to_s.length].max } }

    [ 1, 2, 4 ].each { |c| widths[c] *= -1 if widths[c] }        # right justify these columns
    format = widths.map { |w| "%#{w}s" }.join(' ')

    lines.each { |line| puts(format % line) }
    stanza += 1
  end
end

# exit success (0) if any matches found
exit(matched ? 0 : 1)

# vim:filetype=ruby:ts=8:sts=2:et:sta
