# mhf-fake-client
A proof-of-concept CLI fake client for MHF.

Run with:
```
py -3 fake_client.py cog <ID> <PASSWORD>
```

To login via the COG jp web api, sign server (using the previous skey), and get the and parse the world/channel list from the entrance server.

Or simply:
```
py -3 fake_client.py channel_test
```

To print the JP channel list. (Unauthenticated)