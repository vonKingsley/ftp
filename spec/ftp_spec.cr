require "./spec_helper"

def ftp
  FTP::Client.new("localhost", username: username, password: password)
end

def ftp(&block)
  FTP::Client.new("localhost", username: username, password: password).tap do |client|
    yield client
    client.close
  end
end

def tls
  FTP::Client.new("localhost", username: username, password: password, tls: true)
end

describe FTP do
  #it "takes no args" do
  #  ftp = FTP::Client.new
  #  ftp.should be_a(FTP::Client)
  #end

  it "takes a host" do
    ftp = FTP::Client.new("localhost")
    ftp.should be_a(FTP::Client)
    ftp.host.should eq "localhost"
    ftp.close
  end

  it "takes a block" do
    FTP::Client.open("localhost", username: username, password: password) do |client|
      client.nlst.should contain("the_tree.txt")
      client.rename("the_tree.txt", "renamed.txt")
      client.nlst.should_not contain("the_tree.txt")
      client.nlst.should contain("renamed.txt")
      client.rename("renamed.txt", "the_tree.txt")
    end
  end

  it "takes a host and username and password" do
    (ftp.welcome).should contain "230"
  end

  it "has the last response code" do
    client = ftp
    client.size("chompers.jpg")
    client.last_response_code.should eq "213"
    client.close
  end

  it "has the last response" do
    client = ftp
    client.noop
    client.last_response.should contain "200"
    client.close
  end

  it "lists dir" do
    client = ftp
    (client.list.any? { |s| s.includes?("chompers") }).should be_true
    client.close
  end

  it "lists filenames" do
    client = ftp
    (client.nlst).should contain("the_tree.txt")
    client.close
  end

  #vsftpd has not implemented MLST and MLSD
  it "#mlst" do
    ftp do |c|
      c.mlst("./new_dir").facts["type"].should eq "dir"
    end
  end

  it "#mlsd" do
    ftp do |c|
      c.mlsd("./new_dir").last.facts["size"].should eq 477
    end
  end

  it "filename size" do
    ftp do |c|
      sz = c.size "chompers.jpg"
      sz.should eq 214490
    end
  end

  it "changes directory" do
    client = ftp
    client.chdir("new_dir")
    client.nlst.should contain("low_tide.txt")
    client.close
  end

  it "returns the pwd" do
    client = ftp
    client.chdir("new_dir")
    client.pwd.should eq "/new_dir"
    client.close
  end

  it "returns the size of file" do
    ftp do |c|
      (c.size("the_tree.txt")).should eq 654
    end
  end

  it "has help info" do
    ftp do |c|
      (c.help).should contain("214")
    end
  end

  it "#site" do
    # TODO: Fix
    ftp.site("HELP").should eq nil
  end

  it "#status" do
    ftp do |c|
      c.status.should contain "211"
    end
  end

  it "uses status with a path" do
    ftp do |c|
      (c.status "./new_dir").should contain "213"
    end
  end

  it "#system" do
    ftp do |c|
      c.system.should eq "UNIX Type: L8"
    end
  end

  it "#mdtm" do
    file = "./chompers.jpg"
    ftp do |c|
      (c.mdtm file).should eq "20170821221610"
    end
  end

  it "renames a remote file" do
    ftp do |c|
      c.nlst.should contain("the_tree.txt")
      c.rename("the_tree.txt", "renamed.txt")
      c.nlst.should_not contain("the_tree.txt")
      c.nlst.should contain("renamed.txt")
      c.rename("renamed.txt", "the_tree.txt")
    end
  end

  it "gets a remote text file" do
    file = "the_tree.txt"
    ftp do |c|
      c.get_text_file(file)
    end
    File.exists?(file).should be_true
    File.delete(file)
  end

  it "gets a remote text file in a dir" do
    remote_file = "new_dir/low_tide.txt"
    base = File.basename(remote_file)
    ftp do |c|
      c.get_text_file(remote_file)
    end
    File.exists?(base).should be_true
    File.empty?(base).should be_false
    File.delete(base)
  end

  it "gets a remote text file and saves it with a new name" do
    remote_file = "new_dir/low_tide.txt"
    local_file = "mylocal.txt"
    ftp do |c|
      c.get_text_file(remote_file, local_file)
    end
    File.exists?(local_file).should be_true
    File.empty?(local_file).should be_false
    File.delete(local_file)
  end

  it "gets a new file and passes line by line to block" do
    # TODO
  end

  it "puts a text file and deletes it" do
    client = ftp
    client.chdir("new_dir")
    client.put_text_file(local_textfile, "text_file.txt")
    client.nlst.should contain("text_file.txt")
    client.delete("text_file.txt")
    client.close
  end

  it "puts a text file with a block" do
    # TODO
  end

  it "gets a binary file" do
    file = "chompers.jpg"
    ftp do |c|
      c.get_binary_file(file)
    end
    File.exists?(file).should be_true
    File.delete(file)
  end

  it "keeps the same filesize" do
    file = "chompers.jpg"
    ftp do |c|
      c.get_binary_file(file)
    end
    remote_size = ftp.size file
    local_size = File.size(file)
    local_size.should eq remote_size
    File.delete(file)
  end

  it "handles a file that doesn't exist" do
    # TODO
  end

  it "puts a binary file" do
    client = ftp
    base = File.basename(local_binaryfile)
    client.put_binary_file(local_binaryfile)
    client.nlst.should contain(File.basename(base))
    client.delete(base)
    client.close
  end

  it "closes the socket" do
    client = ftp
    client.chdir("new_dir")
    client.close
    client.closed?.should be_true
  end

  #vsftpd does not seem to accept the abor command until after the download is complete
  #if you can tell me what i did wrong, open an issue for me and let me know.
  #pureftp works great and i wasted way to much time trying to get vsftpd working on this
  it "aborts the current data link" do
    large = "large.zip"
    client = ftp
    channel = Channel(String | Nil).new(2)
    spawn do
      channel.send client.get_binary_file(large)
    end
    sleep 1
    abor = client.abort
    ["225", "226", "426"].should contain abor[0,3]
    channel.receive
    ["150","226"].should contain client.last_response_code
    client.close
    File.delete(large)
  end

  it "does TLS" do
    tls.welcome.should contain "230"
  end

  it "closes the tls socket" do
    client = tls
    client.chdir("new_dir")
    client.close
    client.closed?.should be_true
  end

  it "gets a binary file in tls mode" do
  file = "chompers.jpg"
    tls.get_binary_file(file)
    File.exists?(file).should be_true
    File.delete(file)
  end
end
