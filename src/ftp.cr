# = ftp.cr - FTP Client Library
#
# Based off of Net::FTP written by Shugo Maeda <shugo@ruby-lang.org>.
#

require "./ftp/*"
require "socket"
require "mutex"
require "time"

class Socket
  # Send out of bound data
  #
  # MSG_OOB is used with FTP during ABRT and SYST commands
  # MSG_OOB = 0x1 in sys/socket.h
  def send_oob(message)
    slice = message.to_slice
    bytes_sent = LibC.send(fd, slice.to_unsafe.as(Void*), slice.size, 0x1)
    raise Errno.new("Error sending datagram") if bytes_sent == -1
    bytes_sent
  ensure
    # see IO::FileDescriptor#unbuffered_write
    if (writers = @writers) && !writers.empty?
      add_write_event
    end
  end
end

#Hacky to reopen openssl scoket and re-extend it to include above
class OpenSSL::SSL::Socket < Socket; end

{% if !flag?(:without_openssl) %}
  require "openssl"
{% end %}

module FTP
  class FTPError < Exception; end

  class FTPReplyError < FTPError; end

  class FTPTempError < FTPError; end

  class FTPPermError < FTPError; end

  class FTPProtoError < FTPError; end

  class FTPConnectionError < FTPError; end

  # :startdoc:

  #
  # This class implements the File Transfer Protocol.  If you have used a
  # command-line FTP program, and are familiar with the commands, you will be
  # able to use this class easily.  Some extra features are included to take
  # advantage of Ruby's style and strengths.
  #
  # == Example
  #
  #   require 'ftp'
  #
  # === Example 1
  # ```crystal
  #   ftp = Net::FTP.new('example.com')
  #   ftp.login
  #   files = ftp.chdir('pub/lang/ruby/contrib')
  #   files = ftp.list('n*')
  #   ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
  #   ftp.close
  # ```
  # === Example 2
  # ```crystal
  #   Net::FTP.open('example.com') do |ftp|
  #     ftp.login
  #     files = ftp.chdir('pub/lang/ruby/contrib')
  #     files = ftp.list('n*')
  #     ftp.getbinaryfile('nif.rb-0.91.gz', 'nif.gz', 1024)
  #   end
  # ```
  # == Major Methods
  #
  # The following are the methods most likely to be useful to users:
  # - Client.open
  # - #get_binary_file
  # - #get_text_file
  # - #put_binary_file
  # - #put_text_file
  # - #chdir
  # - #nlst
  # - #size
  # - #rename
  # - #delete
  #
  class Client
    include OpenSSL
    include SSL

    #:stopdoc:
    CRLF  = "\r\n"
    MUTEX = Mutex.new
    #:startdoc:

    FTP_PORT = 21
    DEFAULT_BLOCKSIZE = IO::Buffered::BUFFER_SIZE

    # When +true+, transfers are performed in binary mode.
    # Default: +true+.
    getter :binary
    @binary = true

    # When +true+, the connection is in passive mode.
    # Default: +true+.
    property :passive
    @passive = true

    # When +true+, all traffic to and from the server is written
    # to +$stdout+.
    # Default: +false+.
    property :debug_mode
    @debug_mode = false

    # Sets or retrieves the +resume+ status, which decides whether incomplete
    # transfers are resumed or restarted.
    # Default: +false+.
    property :resume
    @resume = false

    # Number of seconds to wait for the connection to open. Any number
    # may be used, including Floats for fractional seconds. If the FTP
    # object cannot open a connection in this many seconds, it raises a
    # Net::OpenTimeout exception.
    # Default +120+.
    property :open_timeout
    @open_timeout = 120

    # Number of seconds to wait for the TLS handshake. Any number
    # may be used, including Floats for fractional seconds. If the FTP
    # object cannot complete the TLS handshake in this many seconds, it
    # raises a Net::OpenTimeout exception. The default value is +120+.
    # If +ssl_handshake_timeout+ is +nil+, +open_timeout+ is used instead.
    property :ssl_handshake_timeout
    @ssl_handshake_timeout = @open_timeout

    # Number of seconds to wait for one block to be read (via one read(2)
    # call). Any number may be used, including Floats for fractional
    # seconds. If the FTP object cannot read data in this many seconds,
    # it raises a Timeout::Error exception.
    # Default +60 seconds+
    getter :read_timeout
    @read_timeout = 60

    # Setter for the read_timeout attribute.
    def read_timeout=(sec)
      @socket.as(TCPSocket).read_timeout = sec
      @read_timeout = sec
    end

    property :ssl_options
    @ssl_options = OpenSSL::SSL::Options::ALL

    # The server's welcome message.
    getter :welcome
    @welcome = ""

    # The server's last response code.
    getter :last_response_code
    @last_response_code : String = ""

    # The server's last response.
    getter :last_response
    @last_response : String = ""

    #
    # A synonym for <tt>FTP::Client.new</tt>.
    #
    # If a block is given, it is passed the +FTP+ object, which will be closed
    # when the block finishes, or when an exception is raised.
    #
    def Client.open(host, **args)
      ftp = new(host, **args)
      begin
        yield ftp
      ensure
        ftp.close
      end
    end

    def Client.open(host, *args)
      new(host, **args)
    end

    # :call-seq:
    #    FTP::Client.new(host = nil, username: "", password: "")
    #
    # Creates and returns a new +FTP::Client+ object. If a +host+ is given, a connection
    # is made.
    #
    # +options+ is an option hash, each key of which is a symbol.
    #
    # The available options are:
    #
    # port:      Port number (default value is 21)
    # tls:       If tls: is true, then an attempt will be made
    #             to use SSL (now TLS) to connect to the server.  For this
    #             to work OpenSSL [OSSL] and the Ruby OpenSSL [RSSL]
    #             extensions need to be installed.  If options[:ssl] is a
    #             hash, it's passed to OpenSSL::SSL::SSLContext#set_params
    #             as parameters.
    # username::  Username for login.  If options[:username] is the string
    #             "anonymous" and the options[:password] is +nil+,
    #             "anonymous@" is used as a password.
    # password::  Password for login.
    # account::   Account information for ACCT.
    # passive::   When +true+, the connection is in passive mode. Default:
    #             +true+.
    # open_timeout::  Number of seconds to wait for the connection to open.
    #                 See Net::FTP#open_timeout for details.  Default: +nil+.
    # read_timeout::  Number of seconds to wait for one block to be read.
    #                 See Net::FTP#read_timeout for details.  Default: +60+.
    # ssl_handshake_timeout::  Number of seconds to wait for the TLS
    #                          handshake.
    #                          See Net::FTP#ssl_handshake_timeout for
    #                          details.  Default: +nil+.
    # debug_mode::  When +true+, all traffic to and from the server is
    #               written to +$stdout+.  Default: +false+.
    #
    getter host
    @host : String
    @port : Int32
    @ssl_context : OpenSSL::SSL::Context::Client?
    @bare_socket : TCPSocket | Nil
    @socket : TCPSocket | OpenSSL::SSL::Socket | Nil
    def initialize(@host, @port = FTP_PORT, *, username = nil, password = nil, acct = nil, @tls = false, **options) # options = {} of Symbol => Nil | Bool | OpenSSL::SSL::Options )
      if @tls
        {% if flag?(:without_openssl) %}
          raise "FTP::Client TLS is disabled because `-D without_openssl` was passed at compile time"
        {% end %}
        @ssl_context = OpenSSL::SSL::Context::Client.new
        @ssl_context.not_nil!.add_options(ssl_options)
      else
        @ssl_context = nil
      end
      #@bare_socket = @socket = TCPSocket.new
      @logged_in = false
      if host
        connect(host, port)
        if username
          login(username, password, acct)
        end
      end
    end

    # A setter to toggle transfers in binary mode.
    # +newmode+ is either +true+ or +false+
    def binary=(newmode)
      if newmode != @binary
        @binary = newmode
        send_type_command if @logged_in
      end
    end

    # Sends a command to destination host, with the current binary sendmode
    # type.
    #
    # If binary mode is +true+, then "TYPE I" (image) is sent, otherwise "TYPE
    # A" (ascii) is sent.
    private def send_type_command
      if @binary
        voidcmd("TYPE I")
      else
        voidcmd("TYPE A")
      end
    end

    # Toggles transfers in binary mode and yields to a block.
    # This preserves your current binary send mode, but allows a temporary
    # transaction with binary sendmode of +newmode+.
    #
    # +newmode+ is either +true+ or +false+
    private def with_binary(newmode) # :nodoc:
      oldmode = binary
      self.binary = newmode
      begin
        yield
      ensure
        self.binary = oldmode
      end
    end

    private def connection_socket
      socket = @socket
      return socket if socket
      socket = TCPSocket.new @host, @port, nil, @open_timeout
      socket.read_timeout = @read_timeout
      socket.sync = false
      @socket = @bare_socket = socket
      socket
    end

    private def connection_socket(@host, @port)
      connection_socket
    end

    # The data socket is to transfer data across
    # part of PASV
    private def data_socket(host, port)
      TCPSocket.new(host, port, nil, @open_timeout)
    end

    # Crystal needs to implement OpenSSL::SSL::Session to fully support FTP
    # most servers require session reuse for ssl
    # for ABRT and SYST crystal needs to implement flags for send to support MSG_OOB
    private def start_tls_session(socket)
      hostname = @host || nil
      ssl_context = @ssl_context.not_nil!
      #ssl_context.verify_mode = OpenSSL::SSL::VerifyMode::NONE

      ssl_socket = OpenSSL::SSL::Socket::Client.new(socket, context: ssl_context, sync_close: true, hostname: hostname)
      ssl_socket.sync_close = true
      # crystal doesn't support ssl session
      # if @ssl_session && Time.utc_ticks < @ssl_session.not_nil!.time.to_f + @ssl_session.not_nil!.timeout
      # ProFTPD returns 425 for data connections if session is not reused.
      #  ssl_socket.session = @ssl_session
      # end
      #ssl_socket_connect(ssl_socket, @ssl_handshake_timeout)
      #if @ssl_context.not_nil!.verify_mode != OpenSSL::SSL::VerifyMode::NONE
        #ssl_socket.post_connection_check(@host)
      #end
      # @ssl_session = ssl_socket.session
      return ssl_socket
    rescue e: Exception
      raise(e)
    end

    #
    # Establishes an FTP connection to host, optionally overriding the default
    # port. If the environment variable +SOCKS_SERVER+ is set, sets up the
    # connection through a SOCKS proxy. Raises an exception (typically
    # <tt>Errno::ECONNREFUSED</tt>) if the connection cannot be established.
    #
    def connect(host, port = FTP_PORT)
      if @debug_mode
        print "connect: ", host, ", ", port, "\n"
      end
      MUTEX.synchronize do
        connection_socket(host, port)
        #connects to server response shoud be 220
        voidresp
        if !@ssl_context.nil?
          begin
            voidcmd("AUTH TLS")
            @socket = start_tls_session(@bare_socket.not_nil!)
            voidcmd("PBSZ 0")
            voidcmd("PROT P")
          rescue e : OpenSSL::SSL::Error
            @socket.try &.close
            raise e
          end
        end
      end
    end

    #
    # Set the socket used to connect to the FTP server.
    #
    # May raise FTPReplyError if +get_greeting+ is false.
    def set_socket(socket, get_greeting = true)
      MUTEX.synchronize do
        @socket = socket
        if get_greeting
          voidresp
        end
      end
    end

    # If string +s+ includes the PASS command (password), then the contents of
    # the password are cleaned from the string using "*"
    private def sanitize(str : String) # :nodoc:
      if str =~ /^PASS /i
        return str[0, 5] + "*" * (str.size - 5)
      else
        return str
      end
    end

    # Ensures that +line+ has a control return / line feed (CRLF) and writes
    # it to the socket.
    private def putline(line) # :nodoc:
      if @debug_mode
        print "put: ", sanitize(line), "\n"
      end
      if /[\r\n]/ =~ line
        raise ArgumentError.new("A line must not contain CR or LF")
      end
      line = line + CRLF
      connection_socket.flush_on_newline = true
      connection_socket.write(line.to_slice)
    end

    # Reads a line from the socket.  If EOF, then it will raise EOFError
    private def getline # :nodoc:
      line = connection_socket.gets(false) # if get EOF, nil
      line = line.try &.sub(/(\r\n|\n|\r)\z/, "") || ""
      if @debug_mode
        print "get: ", sanitize(line), "\n"
      end
      return line
    end

    # Receive a section of lines until the response code's match.
    private def getmultiline # :nodoc:
      lines = [] of String
      lines << getline
      code = lines.last[/\A([0-9a-zA-Z]{3})-/, 1]?
      if code
        delimiter = code + " "
        loop do
          lines << getline
          break if lines.last.starts_with?(delimiter)
        end
      end
      return lines.join("\n") + "\n"
    end

    # Receives a response from the destination host.
    #
    # Returns the response code or raises FTPTempError, FTPPermError, or
    # FTPProtoError
    private def getresp # :nodoc:
      @last_response = getmultiline
      @last_response_code = @last_response[0, 3]
      case @last_response_code
      when /\A[123]/
        return @last_response
      when /\A4/
        raise FTPTempError.new(@last_response)
      when /\A5/
        raise FTPPermError.new(@last_response)
      else
        raise FTPProtoError.new(@last_response)
      end
    end

    # Receives a response.
    #
    # Raises FTPReplyError if the first position of the response code is not
    # equal 2.
    private def voidresp # :nodoc:
      resp = getresp
      if !resp.starts_with?("2")
        raise FTPReplyError.new(resp)
      end
    end

    #
    # Sends a command and returns the response.
    #
    def sendcmd(cmd)
      MUTEX.synchronize do
        putline(cmd)
        return getresp
      end
    end

    #
    # Sends a command and expect a response beginning with '2'.
    #
    def voidcmd(cmd)
      MUTEX.synchronize do
        putline(cmd)
        voidresp
      end
    end

    # Constructs and send the appropriate PORT (or EPRT) command
    private def sendport(host, port) # :nodoc:
      if remote_address.family.inet?
        cmd = "PORT " + (host.split(".") + port.divmod(256).to_a).join(",")
      elsif remote_address.family.inet6?
        cmd = sprintf("EPRT |2|%s|%d|", host, port)
      else
        raise FTPProtoError.new(host)
      end
      voidcmd(cmd)
    end

    # Returns a remote address of the Socket
    private def remote_address
      @bare_socket.as(TCPSocket).remote_address
    end

    # Returns a local address of the Socket
    private def local_address
      @bare_socket.as(TCPSocket).local_address
    end

    # Constructs a TCPServer socket
    private def makeport # :nodoc:
      TCPServer.new(local_address.address, 0)
    end

    # sends the appropriate command to enable a passive connection
    private def makepasv # :nodoc:
      if remote_address.family.inet?
        host, port = parse227(sendcmd("PASV"))
      else
        host, port = parse229(sendcmd("EPSV"))
      end
      return host, port
    end

    # Constructs a connection for transferring data
    private def transfercmd(cmd, rest_offset = nil) # :nodoc:
      if @passive
        host, port = makepasv
        conn = data_socket(host, port)
        if @resume && rest_offset
          resp = sendcmd("REST " + rest_offset.to_s)
          if !resp.starts_with?("3")
            raise FTPReplyError.new(resp)
          end
        end
        resp = sendcmd(cmd)
        # skip 2XX for some ftp servers
        resp = getresp if resp.starts_with?("2")
        if !resp.starts_with?("1")
          raise FTPReplyError.new(resp)
        end
      else
        socket = makeport
        begin
          addr = socket.local_address
          p "addr: #{addr}"
          p "Sock: #{socket}"
          sendport(addr.address, addr.port)
          if @resume && rest_offset
            resp = sendcmd("REST " + rest_offset.to_s)
            if !resp.starts_with?("3")
              raise FTPReplyError.new(resp)
            end
          end
          resp = sendcmd(cmd)
          # skip 2XX for some ftp servers
          resp = getresp if resp.starts_with?("2")
          if !resp.starts_with?("1")
            raise FTPReplyError.new(resp)
          end
          conn = socket.accept
          socket.close_write rescue nil
          socket.read(bytes = Bytes.new(DEFAULT_BLOCKSIZE)) rescue nil
        ensure
          socket.close
        end
      end
      conn = (@socket.class == OpenSSL::SSL::Socket::Client) ? start_tls_session(conn) : conn
        #return @socket #start_tls_session(conn)
      #else
        #return conn
      #end
      #conn.read_timeout = @read_timeout
      return conn.not_nil!
    end

    # Logs in to the remote host.  The session must have been
    # previously connected.  If +user+ is the string "anonymous" and
    # the +password+ is +nil+, "anonymous@" is used as a password.  If
    # the +acct+ parameter is not +nil+, an FTP ACCT command is sent
    # following the successful login.  Raises an exception on error
    # (typically <tt>FTPPermError</tt>).
    #
    def login(user = "anonymous", passwd = nil, acct = nil)
      if user == "anonymous" && passwd == nil
        passwd = "anonymous@"
      end
      resp = ""
      MUTEX.synchronize do
        resp = sendcmd("USER " + user)
        if resp.starts_with?("3")
          raise FTPReplyError.new(resp) if passwd.nil?
          resp = sendcmd("PASS " + passwd)
        end
        if resp.starts_with?("3")
          raise FTPReplyError.new(resp) if acct.nil?
          resp = sendcmd("ACCT " + acct)
        end
      end
      if !resp.starts_with?("2")
        raise FTPReplyError.new(resp)
      end
      @welcome = resp
      send_type_command
      @logged_in = true
    end

    #
    # Puts the connection into binary (image) mode, issues the given command,
    # and fetches the data returned, passing it to the associated block in
    # chunks of +blocksize+ characters. Note that +cmd+ is a server command
    # (such as "RETR myfile").
    #
    def retrbinary(cmd, blocksize, rest_offset = nil) # :yield: data
      MUTEX.synchronize do
        with_binary(true) do
          begin
            conn = transfercmd(cmd, rest_offset)
            loop do
              bytes_read = conn.read(data = Bytes.new(blocksize))
              break if bytes_read == 0
              yield(data[0, bytes_read])
            end
            # conn.shutdown(Socket::SHUT_WR)
            #conn.close_write
            conn.flush
            #conn.read_timeout = 1
            conn.read(Bytes.new(DEFAULT_BLOCKSIZE))
          ensure
            conn.close if conn
          end
          voidresp
        end
      end
    end

    #
    # Puts the connection into ASCII (text) mode, issues the given command, and
    # passes the resulting data, one line at a time, to the associated block. If
    # no block is given, prints the lines. Note that +cmd+ is a server command
    # (such as "RETR myfile").
    #
    def retrlines(cmd) # :yield: line
      MUTEX.synchronize do
        with_binary(false) do
          begin
            conn = transfercmd(cmd)
            loop do
              if line = conn.gets(false)
                yield(line.sub(/\r?\n\z/, ""), !line.match(/\n\z/).nil?)
              else
                break
              end
            end
            #conn.close_write
            conn.flush
            #conn.read_timeout = 1
            conn.read(b = Bytes.new(DEFAULT_BLOCKSIZE))
          ensure
            conn.close if conn
          end
          voidresp
        end
      end
    end

    #
    # Puts the connection into binary (image) mode, issues the given server-side
    # command (such as "STOR myfile"), and sends the contents of the file named
    # +file+ to the server. If the optional block is given, it also passes it
    # the data, in chunks of +blocksize+ characters.
    #
    def storbinary(cmd, file, blocksize, rest_offset = nil) # :yield: data
      if rest_offset
        file.seek(rest_offset, IO::Seek::Set)
      end
      MUTEX.synchronize do
        with_binary(true) do
          conn = transfercmd(cmd)
          loop do
            bytes_read = file.read(data = Bytes.new(blocksize))
            break if bytes_read == 0
            conn.write(data[0, bytes_read])
            yield(buf)
          end
          conn.close
          voidresp
        end
      end
    rescue ex : Errno
      if ex.errno == Errno::EPIPE
        # EPIPE, in this case, means that the data connection was unexpectedly
        # terminated.  Rather than just raising EPIPE to the caller, check the
        # response on the control connection.  If getresp doesn't raise a more
        # appropriate exception, re-raise the original exception.
        getresp
        raise ex
      end
    end

    def storbinary(cmd, file, blocksize, rest_offset = nil)
      if rest_offset
        file.seek(rest_offset, IO::Seek::Set)
      end
      MUTEX.synchronize do
        with_binary(true) do
          conn = transfercmd(cmd)
          loop do
            bytes_read = file.read(data = Bytes.new(blocksize))
            break if bytes_read == 0
            conn.write(data[0, bytes_read])
          end
          conn.close
          voidresp
        end
      end
    rescue ex : Errno
      if ex.errno == Errno::EPIPE
        getresp
        raise ex
      end
    end

    #
    # Puts the connection into ASCII (text) mode, issues the given server-side
    # command (such as "STOR myfile"), and sends the contents of the file
    # named +file+ to the server, one line at a time. If the optional block is
    # given, it also passes it the lines.
    #
    def storlines(cmd, file, &block) # :yield: line
      MUTEX.synchronize do
        with_binary(false) do
          conn = transfercmd(cmd)
          loop do
            if buf = file.gets(false)
              buf = buf.chomp + CRLF
            else
              break
            end
            conn.write(buf)
            yield(buf)
          end
          conn.close
          voidresp
        end
      end
    rescue ex : Errno
      if ex.errno == Errno::EPIPE
        # EPIPE, in this case, means that the data connection was unexpectedly
        # terminated.  Rather than just raising EPIPE to the caller, check the
        # response on the control connection.  If getresp doesn't raise a more
        # appropriate exception, re-raise the original exception.
        getresp
        raise ex
      end
    end

    def storlines(cmd, file) # :yield: line
      MUTEX.synchronize do
        with_binary(false) do
          conn = transfercmd(cmd)
          loop do
            if buf = file.gets
              buf = buf.chomp + CRLF
            else
              break
            end
            conn.write(buf.to_slice)
          end
          conn.close
          voidresp
        end
      end
    rescue ex : Errno
      if ex.errno == Errno::EPIPE
        getresp
        raise ex
      end
    end

    #
    # Retrieves +remotefile+ in binary mode, storing the result in +localfile+.
    # If +localfile+ is nil, returns retrieved data.
    # If a block is supplied, it is passed the retrieved data in +blocksize+
    # chunks.
    #
    def get_binary_file(remotefile, localfile = File.basename(remotefile),
                        blocksize = DEFAULT_BLOCKSIZE, &block) # :yield: data
      f = nil
      result = nil
      if localfile
        if @resume
          rest_offset = File.size?(localfile)
          f = open(localfile, "a")
        else
          rest_offset = nil
          f = open(localfile, "w")
        end
      elsif !block_given?
        result = String.new
      end
      begin
        f.try &.binmode
        retrbinary("RETR #{remotefile}", blocksize, rest_offset) do |data|
          f.try &.write(data)
          block(data)
          result.try &.concat(data)
        end
        return result
      ensure
        f.try &.close
      end
    end

    def get_binary_file(remotefile, localfile = File.basename(remotefile),
                        blocksize = DEFAULT_BLOCKSIZE)
      result = nil
      if @resume
        rest_offset = File.size(localfile)
        f = File.open(localfile, "ab")
      else
        rest_offset = nil
        f = File.open(localfile, "wb")
      end
      begin
        retrbinary("RETR #{remotefile}", blocksize, rest_offset) do |data|
          f.write(data)
          result.try &.concat(data)
        end
        return result
      ensure
        f.close
      end
    end

    #
    # Retrieves +remotefile+ in ASCII (text) mode, storing the result in
    # +localfile+.
    # If +localfile+ is nil, returns retrieved data.
    # If a block is supplied, it is passed the retrieved data one
    # line at a time.
    #
    def get_text_file(remotefile, localfile = File.basename(remotefile),
                      &block) # :yield: line
      f = nil
      result = nil
      if localfile
        f = File.open(localfile, "w")
      elsif !block_given?
        result = String.new
      end
      begin
        retrlines("RETR #{remotefile}") do |line, newline|
          l = newline ? line + "\n" : line
          f.try &.print(l)
          block(line, newline)
          result.try &.concat(l)
        end
        return result
      ensure
        f.try &.close
      end
    end

    def get_text_file(remotefile, localfile = File.basename(remotefile))
      f = nil
      result = nil
      if localfile
        f = File.open(localfile, "w")
      end
      begin
        retrlines("RETR #{remotefile}") do |line, newline|
          l = newline ? line + "\n" : line
          f.try &.print(l)
          result.try &.concat(l)
        end
        return result
      ensure
        f.try &.close
      end
    end

    #
    # Retrieves +remotefile+ in whatever mode the session is set (text or
    # binary).  See #gettextfile and #getbinaryfile.
    #
    def get(remotefile, localfile = File.basename(remotefile),
            blocksize = DEFAULT_BLOCKSIZE, &block) # :yield: data
      if @binary
        getbinaryfile(remotefile, localfile, blocksize, &block)
      else
        gettextfile(remotefile, localfile, &block)
      end
    end

    #
    # Transfers +localfile+ to the server in binary mode, storing the result in
    # +remotefile+. If a block is supplied, calls it, passing in the transmitted
    # data in +blocksize+ chunks.
    #
    def put_binary_file(localfile, remotefile = File.basename(localfile),
                        blocksize = DEFAULT_BLOCKSIZE, &block) # :yield: data
      if @resume
        begin
          rest_offset = size(remotefile)
        rescue Net::FTPPermError
          rest_offset = nil
        end
      else
        rest_offset = nil
      end
      f = open(localfile)
      begin
        f.binmode
        if rest_offset
          storbinary("APPE #{remotefile}", f, blocksize, rest_offset, &block)
        else
          storbinary("STOR #{remotefile}", f, blocksize, rest_offset, &block)
        end
      ensure
        f.close
      end
    end

    def put_binary_file(localfile, remotefile = File.basename(localfile),
                        blocksize = DEFAULT_BLOCKSIZE)
      if @resume
        begin
          rest_offset = size(remotefile)
        rescue FTPPermError
          rest_offset = nil
        end
      else
        rest_offset = nil
      end
      f = File.open(localfile)
      begin
        if rest_offset
          storbinary("APPE #{remotefile}", f, blocksize, rest_offset)
        else
          storbinary("STOR #{remotefile}", f, blocksize, rest_offset)
        end
      ensure
        f.close
      end
    end

    #
    # Transfers +localfile+ to the server in ASCII (text) mode, storing the result
    # in +remotefile+. If callback or an associated block is supplied, calls it,
    # passing in the transmitted data one line at a time.
    #
    def put_text_file(localfile, remotefile = File.basename(localfile), &block) # :yield: line
      f = open(localfile)
      begin
        storlines("STOR #{remotefile}", f, &block)
      ensure
        f.close
      end
    end

    def put_text_file(localfile, remotefile = File.basename(localfile)) # :yield: line
      f = File.open(localfile)
      begin
        storlines("STOR #{remotefile}", f)
      ensure
        f.close
      end
    end

    #
    # Transfers +localfile+ to the server in whatever mode the session is set
    # (text or binary).  See #puttextfile and #putbinaryfile.
    #
    def put(localfile, remotefile = File.basename(localfile),
            blocksize = DEFAULT_BLOCKSIZE, &block)
      if @binary
        putbinaryfile(localfile, remotefile, blocksize, &block)
      else
        puttextfile(localfile, remotefile, &block)
      end
    end

    #
    # Sends the ACCT command.
    #
    # This is a less common FTP command, to send account
    # information if the destination host requires it.
    #
    def acct(account)
      cmd = "ACCT " + account
      voidcmd(cmd)
    end

    #
    # Returns an array of filenames in the remote directory.
    #
    def nlst(dir = nil)
      cmd = "NLST"
      if dir
        cmd = "#{cmd} #{dir}"
      end
      files = [] of String
      retrlines(cmd) do |line|
        files.push(line)
      end
      return files
    end

    #
    # Returns an array of file information in the directory (the output is like
    # `ls -l`).
    #
    def list(*args)
      cmd = "LIST"
      args.each do |arg|
        cmd = "#{cmd} #{arg}"
      end
      lines = [] of String
      retrlines(cmd) do |line|
        lines << line
      end
      return lines
    end

    #
    # MLSxEntry represents an entry in responses of MLST/MLSD.
    # Each entry has the facts (e.g., size, last modification time, etc.)
    # and the pathname.
    #
    class MLSxEntry
      getter facts : Hash(String, Int32 | String | Time)
      getter pathname : String

      def initialize(@facts, @pathname)
      end

      STANDARD_FACTS = ["size", "modify", "create", "type", "unique", "perm",
                        "lang", "media-type", "charset"]
      {% for name, index in STANDARD_FACTS %}
        def {{name.id.gsub(/-/, "_")}}
          facts[{{name}}]
        end
      {% end %}

      #
      # Returns +true+ if the entry is a file (i.e., the value of the type
      # fact is file).
      #
      def file?
        return facts["type"] == "file"
      end

      #
      # Returns +true+ if the entry is a directory (i.e., the value of the
      # type fact is dir, cdir, or pdir).
      #
      def directory?
        if /\A[cp]?dir\z/.match(facts["type"])
          return true
        else
          return false
        end
      end

      #
      # Returns +true+ if the APPE command may be applied to the file.
      #
      def appendable?
        return facts["perm"].include?('a')
      end

      #
      # Returns +true+ if files may be created in the directory by STOU,
      # STOR, APPE, and RNTO.
      #
      def creatable?
        return facts["perm"].include?('c')
      end

      #
      # Returns +true+ if the file or directory may be deleted by DELE/RMD.
      #
      def deletable?
        return facts["perm"].include?('d')
      end

      #
      # Returns +true+ if the directory may be entered by CWD/CDUP.
      #
      def enterable?
        return facts["perm"].include?('e')
      end

      #
      # Returns +true+ if the file or directory may be renamed by RNFR.
      #
      def renamable?
        return facts["perm"].include?('f')
      end

      #
      # Returns +true+ if the listing commands, LIST, NLST, and MLSD are
      # applied to the directory.
      #
      def listable?
        return facts["perm"].include?('l')
      end

      #
      # Returns +true+ if the MKD command may be used to create a new
      # directory within the directory.
      #
      def directory_makable?
        return facts["perm"].include?('m')
      end

      #
      # Returns +true+ if the objects in the directory may be deleted, or
      # the directory may be purged.
      #
      def purgeable?
        return facts["perm"].include?('p')
      end

      #
      # Returns +true+ if the RETR command may be applied to the file.
      #
      def readable?
        return facts["perm"].include?('r')
      end

      #
      # Returns +true+ if the STOR command may be applied to the file.
      #
      def writable?
        return facts["perm"].include?('w')
      end
    end

    alias FactValueProc = Proc(String, String) | Proc(String, Int32) | Proc(String, Time)
    CASE_DEPENDENT_PARSER   = ->(value : String) { value }
    CASE_INDEPENDENT_PARSER = ->(value : String) { value.downcase }
    DECIMAL_PARSER          = ->(value : String) { value.to_i }
    OCTAL_PARSER            = ->(value : String) { value.to_i(8) }
    TIME_PARSER             = ->(value : String) {
      unless match = value.match(/\A(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})(?<hour>\d{2})(?<min>\d{2})(?<sec>\d{2})(\.(?<fractions>\d+))?/x)
        raise FTPProtoError.new("invalid time-val: #{value}")
      end
      time = match.named_captures.each_with_object({} of String => Int32) { |(k, v), h| h[k] = v.try(&.to_i) || 0 }
      usec = 0
      if fractions = time["fractions"]
        usec = fractions.to_i * 10 ** (6 - fractions.to_s.size)
      end
      Time.new(time["year"], time["month"], time["day"], time["hour"], time["min"], time["sec"], usec, Time::Kind::Utc)
    }
    FACT_PARSERS = Hash(String, FactValueProc).new(CASE_DEPENDENT_PARSER)
    FACT_PARSERS["sizd"] = DECIMAL_PARSER
    FACT_PARSERS["size"] = DECIMAL_PARSER
    FACT_PARSERS["modify"] = TIME_PARSER
    FACT_PARSERS["create"] = TIME_PARSER
    FACT_PARSERS["type"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["unique"] = CASE_DEPENDENT_PARSER
    FACT_PARSERS["perm"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["lang"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["media-type"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["charset"] = CASE_INDEPENDENT_PARSER
    FACT_PARSERS["unix.mode"] = OCTAL_PARSER
    FACT_PARSERS["unix.owner"] = DECIMAL_PARSER
    FACT_PARSERS["unix.group"] = DECIMAL_PARSER
    FACT_PARSERS["unix.ctime"] = TIME_PARSER
    FACT_PARSERS["unix.atime"] = TIME_PARSER

    private def parse_mlsx_entry(entry)
      facts, pathname = entry.chomp.split(/ /, 2)
      unless pathname
        raise FTPProtoError.new(entry)
      end
      fact_hash = facts.scan(/(.*?)=(.*?);/).each_with_object({} of String => (String | Int32 | Time)) { |(match, factname, value), h|
        name = factname.downcase
        h[name] = FACT_PARSERS[name].call(value)
      }
      return MLSxEntry.new(fact_hash, pathname)
    end

    #
    # Returns data (e.g., size, last modification time, entry type, etc.)
    # about the file or directory specified by +pathname+.
    # If +pathname+ is omitted, the current directory is assumed.
    #
    def mlst(pathname = nil)
      cmd = pathname ? "MLST #{pathname}" : "MLST"
      resp = sendcmd(cmd)
      if !resp.starts_with?("250")
        raise FTPReplyError.new(resp)
      end
      line = resp.lines[1]
      unless line
        raise FTPProtoError.new(resp)
      end
      entry = line.sub(/\A(250-| *)/, "")
      return parse_mlsx_entry(entry)
    end

    #
    # Returns an array of the entries of the directory specified by
    # +pathname+.
    # Each entry has the facts (e.g., size, last modification time, etc.)
    # and the pathname.
    # If a block is given, it iterates through the listing.
    # If +pathname+ is omitted, the current directory is assumed.
    #
    def mlsd(pathname = nil, &block) # :yield: entry
      cmd = pathname ? "MLSD #{pathname}" : "MLSD"
      entries = [] of MLSxEntry
      retrlines(cmd) do |line|
        entries << parse_mlsx_entry(line)
      end
      if block
        entries.each(&block)
      end
      return entries
    end

    def mlsd(pathname = nil)
      cmd = pathname ? "MLSD #{pathname}" : "MLSD"
      entries = [] of MLSxEntry
      retrlines(cmd) do |line|
        entries << parse_mlsx_entry(line)
      end
      return entries
    end
    #
    # Renames a file on the server.
    #
    def rename(fromname, toname)
      resp = sendcmd("RNFR #{fromname}")
      if !resp.starts_with?("3")
        raise FTPReplyError.new(resp)
      end
      voidcmd("RNTO #{toname}")
    end

    #
    # Deletes a file on the server.
    #
    def delete(filename)
      resp = sendcmd("DELE #{filename}")
      if resp.starts_with?("250")
        return
      elsif resp.starts_with?("5")
        raise FTPPermError.new(resp)
      else
        raise FTPReplyError.new(resp)
      end
    end

    #
    # Changes the (remote) directory.
    #
    def chdir(dirname : String)
      if dirname == ".."
        begin
          voidcmd("CDUP")
          return
        rescue e : FTPPermError
          if errmsg = e.message
            errmsg[0, 3] != "500"
            raise e
          end
        end
      end
      cmd = "CWD #{dirname}"
      voidcmd(cmd)
    end

    private def get_body(resp) # :nodoc:
      resp[/\A[0-9a-zA-Z]{3} (.*)$/, 1]
    end

    #
    # Returns the size of the given (remote) filename.
    #
    def size(filename : String)
      with_binary(true) do
        resp = sendcmd("SIZE #{filename}")
        if !resp.starts_with?("213")
          raise FTPReplyError.new(resp)
        end
        return get_body(resp).to_i
      end
    end

    #
    # Returns the last modification time of the (remote) file.  If +local+ is
    # +true+, it is returned as a local time, otherwise it's a UTC time.
    #
    def mtime(filename, local = false)
      return TIME_PARSER.call(mdtm(filename), local)
    end

    #
    # Creates a remote directory.
    #
    def mkdir(dirname)
      resp = sendcmd("MKD #{dirname}")
      return parse257(resp)
    end

    #
    # Removes a remote directory.
    #
    def rmdir(dirname)
      voidcmd("RMD #{dirname}")
    end

    #
    # Returns the current remote directory.
    #
    def pwd
      resp = sendcmd("PWD")
      return parse257(resp)
    end

    #
    # Returns system information.
    #
    def system
      resp = sendcmd("SYST")
      if !resp.starts_with?("215")
        raise FTPReplyError.new(resp)
      end
      return get_body(resp)
    end

    #
    # Aborts the previous command (ABOR command).
    #
    def abort
      line = "ABOR" + CRLF
      print "put: ABOR\n" if @debug_mode
      #@socket.send(line, Socket::MSG_OOB)
      connection_socket.send_oob(line)
      resp = getmultiline
      unless ["426", "226", "225"].includes?(resp[0, 3])
        raise FTPProtoError.new(resp)
      end
      return resp
    end

    #
    # Returns the status (STAT command).
    # pathname - when stat is invoked with pathname as a parameter it acts like
    #            list but alot faster and over the same tcp session.
    #
    def status(pathname = nil)
      line = pathname ? "STAT #{pathname}" : "STAT"
      if /[\r\n]/ =~ line
        raise ArgumentError.new("A line must not contain CR or LF")
      end
      print "put: #{line}\n" if @debug_mode
      #@socket.send(line + CRLF, Socket::MSG_OOB)
      connection_socket.send_oob(line + CRLF)
      return getresp
    end

    #
    # Returns the raw last modification time of the (remote) file in the format
    # "YYYYMMDDhhmmss" (MDTM command).
    #
    # Use +mtime+ if you want a parsed Time instance.
    #
    def mdtm(filename)
      resp = sendcmd("MDTM #{filename}")
      if resp.starts_with?("213")
        return get_body(resp)
      end
    end

    #
    # Issues the HELP command.
    #
    def help(arg = nil)
      cmd = "HELP"
      if arg
        cmd = cmd + " " + arg
      end
      sendcmd(cmd)
    end

    #
    # Exits the FTP session.
    #
    def quit
      voidcmd("QUIT")
    end

    #
    # Issues a NOOP command.
    #
    # Does nothing except return a response.
    #
    def noop
      voidcmd("NOOP")
    end

    #
    # Issues a SITE command.
    #
    def site(arg)
      cmd = "SITE " + arg
      voidcmd(cmd)
    end

    #
    # Closes the connection.  Further operations are impossible until you open
    # a new connection with #connect.
    #
    def close
      if connection_socket && !connection_socket.closed?
        begin
          case socket = @socket
          #when OpenSSL::SSL::Socket
          #  socket.flush
          #  socket.close
          when TCPSocket
            socket.close_write rescue nil
            orig, self.read_timeout = self.read_timeout, 3
            socket.read(bytes = Bytes.new(DEFAULT_BLOCKSIZE)) rescue nil
            socket.close
            self.read_timeout = orig
          end
        ensure
          @socket.not_nil!.close
        end
      end
    end

    #
    # Returns +true+ iff the connection is closed.
    #
    def closed?
      @socket == nil || @socket.not_nil!.closed?
    end

    # handler for response code 227
    # (Entering Passive Mode (h1,h2,h3,h4,p1,p2))
    #
    # Returns host and port.
    private def parse227(resp) # :nodoc:
      if !resp.starts_with?("227")
        raise FTPReplyError.new(resp)
      end
      if m = /\((?<host>\d+(,\d+){3}),(?<port>\d+,\d+)\)/.match(resp)
        return parse_pasv_ipv4_host(m["host"]), parse_pasv_port(m["port"])
      else
        raise FTPProtoError.new(resp)
      end
    end

    # handler for response code 228
    # (Entering Long Passive Mode)
    #
    # Returns host and port.
    private def parse228(resp) # :nodoc:
      if !resp.starts_with?("228")
        raise FTPReplyError.new(resp)
      end
      if m = /\(4,4,(?<host>\d+(,\d+){3}),2,(?<port>\d+,\d+)\)/.match(resp)
        return parse_pasv_ipv4_host(m["host"]), parse_pasv_port(m["port"])
      elsif m = /\(6,16,(?<host>\d+(,(\d+)){15}),2,(?<port>\d+,\d+)\)/.match(resp)
        return parse_pasv_ipv6_host(m["host"]), parse_pasv_port(m["port"])
      else
        raise FTPProtoError.new(resp)
      end
    end

    private def parse_pasv_ipv4_host(s)
      return s.tr(",", ".")
    end

    private def parse_pasv_ipv6_host(s)
      return s.split(/,/).map { |i|
        "%02x" % i.to_i
      }.each_slice(2).map(&.join).join(":")
    end

    private def parse_pasv_port(s)
      return s.split(/,/).map(&.to_i).reduce { |x, y|
        (x << 8) + y
      }
    end

    # handler for response code 229
    # (Extended Passive Mode Entered)
    #
    # Returns host and port.
    private def parse229(resp) # :nodoc:
      if !resp.starts_with?("229")
        raise FTPReplyError.new(resp)
      end
      if m = /\((?<d>[!-~])\k<d>\k<d>(?<port>\d+)\k<d>\)/.match(resp)
        return remote_address.address, m["port"].to_i
      else
        raise FTPProtoError.new(resp)
      end
    end

    # handler for response code 257
    # ("PATHNAME" created)
    #
    # Returns host and port.
    private def parse257(resp) # :nodoc:
      if !resp.starts_with?("257")
        raise FTPReplyError.new(resp)
      end
      return resp[/"(([^"]|"")*)"/, 1].to_s.gsub(/""/, '"')
    end
  end
end
