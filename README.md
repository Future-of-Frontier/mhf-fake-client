# mhf-fake-client
A proof-of-concept CLI fake client for MHF.

## Usage
Run with:
```
py -3 fake_client.py [COMMAND] <OPTIONS>
```

Commands:
* `bruteforce` Bruteforce decrypt and encrypted packet. 
* `download_file` Log into MHF and download the given filename.
* `download_scenarios` Log into MHF and download the scenarios.

Options:
* `--username` MHF username.
* `--password` MHF password.
* `--region` game region (MUST BE `tw` OR `jp`). 
* `--filename` filename to use for the `bruteforce` and `download_file` commands.
* `--start_offset` starting offset for the `download_file` and `download_scenarios` commands. Used as the main quest ID for `download_file`, and the category ID for `download_scenarios`.


## Usage examples
* `py -3 fake_client.py bruteforce --filename some_encrypted_packet.bin` Bruteforce decrypt an encrypted packet
* `py -3 fake_client.py download_file --username <ID> --password <PASSWORD> --region jp --filename 56162d0` Log into MHF JP and download the given filename.
* `py -3 fake_client.py download_file --username <ID> --password <PASSWORD> --region tw --filename _ALL_ --start_offset 50000` Log into MHF TW and download all the quests starting from `50000d0`.  
* `py -3 fake_client.py download_scenarios --username <ID> --password <PASSWORD> --region tw --start_offset 5` Log into MHF tw and download the scenarios starting from category `5`.