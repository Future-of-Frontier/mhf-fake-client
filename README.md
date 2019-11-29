# mhf-fake-client
A proof-of-concept CLI fake client for MHF.

## Usage
Run with:
```
py -3 fake_client.py <OPTION>
```

Options:
* `bruteforce <ENCRYPTED PACKET FILEPATH>` Bruteforce decrypt an encrypted packet
* `download_file <ID> <PASSWORD> <FILENAME>` Log into MHF JP and download the given filename.
* `channel_test` Print the JP channel list. (Unauthenticated)


## File download example
`py -3 fake_client.py <ID> <PASSWORD> 56162d0`