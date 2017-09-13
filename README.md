# FTP

FTP Client library

# Known Issues

Crystal does not yet support OpenSSL Sessions, some servers may require
sessions to be used.

Still working on how I want to pass options.

# Supports

TLS (FTPS)

MSLT

MLSD

## Installation

```yaml
dependencies:
  ftp:
    github: vonkingsley/ft
```


## Usage

```crystal
client = FTP::Client.new(host, username, password)
client.list
client.nlst
client.get_binary_file("file")
client.close
```

```crystal
FTP::Client.open(host, username, password) do |c|
  c.list
  c.rename("old_name", "new_name")
end
```

## Contributing

1. Fork it ( https://github.com/vonKingsley/ftp/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [vonKingsley](https://github.com/vonkingsley) Kingsley Lewis - creator, maintainer
