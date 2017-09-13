require "spec"
require "../src/ftp"


def username
  ""
end

def password
  ""
end

pureftp = "docker -D run -d --name ftpd_server -v #{__DIR__}/assets/remote/:/home/ftpusers/{username} -p 21:21 -p 30000-30059:30000-30059 -e \"PUBLICHOST=localhost\" -e \"USER={your username}\" -e \'PASSWORD={your password}\' -e \"ADDED_FLAGS=-d -d\" -e \"ADDED_FLAGS=-O w3c:/var/log/pure-ftpd/transfer.log\" pureftp"
vsftpd = "docker run -d -v #{__DIR__}/assets/remote/:/home/vsftpd -p 20:20 -p 21:21 -p 47400-47470:47400-47470 -e FTP_USER={username} -e FTP_PASS={password} -e PASV_ADDRESS=127.0.0.1 --name ftp --restart=always {Your build image}"

puts "Dockerfile and vsftpd.conf in asset directory."
puts "Dockerfile for pureftp in asset directory"
puts "To run the specs the following docker command needs to run for vsftpd:"
puts vsftpd
puts
puts "To run the specs the following docker command needs to run for pureftp:"
puts pureftp

def local
  "#{__DIR__}/assets/local/"
end

def local_textfile
  local + "falsehood.txt"
end

def local_binaryfile
  local + "happy_chompers.jpg"
end
