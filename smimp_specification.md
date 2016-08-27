## Simple Messaging and Identity Management Protocol

Version: v0.1

Author: [Adam Caudill](https://adamcaudill.com/) (adam@adamcaudill.com)

### Copyright & Intellectual Property Statement

Copyright 2014 - 2016, Adam Caudill.

In the interest of this specification being used freely, this specification in released under the [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) license. See LICENSE for more details.

This work is dedicated to the public good, and it’s the intention of the authors that it be freely available to the public, and the technology be freely usable. Security is a universal right of all people, the purpose of this work is to protect and preserve that right in the face of those that seek to destroy it globally.

### Special Thanks

A special thanks goes out to those that have helped make this possible - without them, this never would have happened.

* [Taylor Hornby](https://defuse.ca/)
* [Brandon Wilson](http://brandonw.net/)
* [Graham Smith](https://twitter.com/neuegram)
* [Marsh Ray](https://twitter.com/marshray)
* [Scott Arciszewski](https://paragonie.com/)

### Document Status

This specification is in development, and subject to change at any time. A formal release will be announced when the document is considered to be stable. Until such time, it is recommended that care be exercised when implementing this, as breaking changes may be introduced. Once a formal release is announced, the document will be frozen, and any future changes will occur in a new version.

### Introduction

SMIMP is a communication and identity system designed to address the modern threats that weren’t considered when the traditional email system was designed. Transparent encryption, forward secrecy, simple self hosting, auditable user information, and strong privacy are all baked into the design from the beginning.

Traditional email has failed to keep up with modern threats, this system aims to address those failings.

### Design Goals

Here are the primary goals of the project, goals that must be met to consider this effort a success:

**Transparent Crypto** - The user must not be required to take any action for a message to be encrypted. All messages must be encrypted, with no option to disable. It must be impossible for a message to “fail open” and expose contents to a third party.

**Strong Crypto** - Strong cryptography should be used throughout the system. To simplify implementation and assure security, libsodium should be used for all possible operations. Implementors should be discouraged from rolling their own implementations.

**Simple Public Key Lookup** - An address should be tied to a single public key, and a public key tied to a single address. 

**Verifiable User History** - Every change to a user’s identity information (change of key, change of server(s), etc.) must be signed by the user’s private key, and contain the hash of the last change. This provides a hash chain from the initial user creation record to current, allowing clients to easily detect manipulation.

**Forward Secrecy** - The user should be able to upload single use public keys, signed by their master key, so that past message contents can’t be revealed if their master private key is compromised.

**Ease of Implementation** - The design should be simple enough that core components can be easily implemented, allowing for a healthy market for clients and servers.

**Minimal New Protocols** - Whenever possible, existing protocols, such as HTTPS, should be used instead of creating a new protocol.

**Simple Self Hosting** - Due to attacks against large providers (hacks and rubber stamp courts), it should be simple to run your own SMIMP mail server, on a commodity VPS server. A user should not need to be an experienced server administrator to successfully run their own server.

**Firewall Friendly** - All message transport should be over HTTPS to remove the need for administrators to open ports on the firewall. This also minimizes the opportunities for filtering, as all message transport will be legitimate HTTPS traffic, and thus harder to distinguish from other traffic.

**Proof of Work** - Messages will each have a proof of work associated with it as an anti-spam measure; the receiving mail server is responsible for determining the difficulty based on factors of its choosing.

### System Overview

SMIMP can be divided into two major parts; identity management and messaging. The identity management system is the core of the design, which the messaging system leverages and builds upon. The identity management system can leverage for other systems, and such use is encouraged.

It was deemed necessary that identity management be part of a new messaging solution to at least partially address the issues of tying a public key to an identity. In this design, control of the messaging address (SMIMP address) is tied entirely to the control of the master key pair created when the account was created.

#### Identity Management

When an account is created, a public key is listed in the publicly available data. Any changes that are made include a signed hash of the change set and the last signature, so that anyone can follow the signed chain from the original creation of the account to the current state.

This information may optionally include pointers to their social media accounts, and other information to help tie identities together.

The system follows a trust on first use model, storing public keys on the first access of a recipient's information to detect if the information is being manipulated. While this is not ideal from an authentication perspective, it is leaps and bounds ahead of what users have today, and without adding unreasonable complication.

Everything is transported over HTTPS, data is transmitted as JSON documents over a REST-like interface.

#### Messaging

The messaging system is intended to be as simple as possible, using information from the identity system, and the same transport mechanism. Messages are transmitted as JSON documents, with as much data encrypted as possible, providing minimal plaintext data that could be intercepted.

Clients connect directly to a recipient's server to collect recipient data (keys), and to send the message. Messages are not relayed by multiple servers as is the case with traditional email.

### Specification

The design of this system is still evolving, and some areas do not have the level of detail needed to build a full implementation; this will be corrected before version 1.0 of this document is released.

The intention is that as much detail as possible be made available to the public for review and comment as soon as possible, to build the best possible standard, prior to any implementations being built. So when reviewing, please keep this status in mind.

### Concepts & Notes

#### Finding Mail Servers

To find a user’s mail server, the client parse the domain part of the address, and pull the `/.well-known/smimp.txt` file for the domain (`https://example.com/.well-known/smimp.txt`). The file should contain one fully qualified domain name; if more than one are found, only the first should be used.

smimp.txt: `smimp.example.com`

The domain specified will be used as the base address for all operation with the server. The protocol specifier (`https://`) is optional; the client is responsible for adding it if missing. Any record that specifies `http://` is invalid, and must not be used.

The domain specified in `sminmp.txt` may also include a path, to which the standard API paths will be appended to.

smimp.txt: `https://smimp.example.com/smimp/`

#### HTTPS Transport

To protect unencrypted metadata (data necessary for server operation), all data must be sent over a secure connection. If the URL specified is not HTTPS, or the client is redirected to a non-HTTPS URL, the client must fail closed - sending no data, and treat the event as a protocol error.

At no time may data be sent in the clear, or over an untrusted connection. In the case that a server returns an invalid, expired, or self-signed certificate, the client must not send any data. It is recommended that clients perform certificate pinning against well known hosts, when possible.

#### Ephemeral & Non-Ephemeral Keys

The client will upload multiple ephemeral public keys via the `ephemeral_keys` API, and a single non-ephemeral public key via the `nonephemeral_key` API. Once an ephemeral public key is returned via the `get_user` API, it will be deleted from the server. If the supply of ephemeral keys is exhausted, the server will begin returning the non-ephemeral key.

These keys may be replaced at any time by the client. The server may issue the ephemeral keys in any order, though the non-ephemeral key may not be issued while there are ephemeral keys available.

There must be one, and only one, non-ephemeral key at all times.

All keys will be `curve25519xsalsa20poly1305` keys, as generated by the libsodium `crypto_box_keypair` method.

#### Address Format

SMIMP address will be defined using the following pattern:

`[alphanum]#{domain}`

Where `[alphanum]` is A-Z, a-z, 0-9 - no spaces or special characters allowed; `{domain}` shall be a valid domain name, sub-domain are valid. The local part and domain will be separated by a hash mark (#). The local part is case insensitive, and the normalized form is lowercase.

### Public Data (Unauthenticated)

#### Server Version Request (Required)

The server will expose the versions of the SMIMP protocol it supports via a `/version` API endpoint. A client that performs a `GET` request to `{url}/version` shall receive a JSON document, including an array of strings, each string represents a version supported. 

The first request a client makes to a server should be to retrieve the versions supported; the client should then select the greatest common version. The version number will be included in the URL for all future API calls, in the following format:

`{url}/{version}/{endpoint}`

Looking something like this:

`https://smimp.example.com/0.1/get_user`

#### Server Information Request (Required)

To get information about what APIs a server implements, the `server_information` API should be called. This will return an array of API names the server implements. As are all other APIs (except `version`), this is called on a specific version, and different versions may implement different features.

Clients should call this the first time they connect to a server, to determine what the server can or can’t do. Some APIs are required, and all compliant servers must implement them, others are optional, as they only apply to specific use cases.

Clients may want to cache this information, refreshing periodically in case of changes.

#### Get User Information (Required)

The get_user API endpoint is used by the client to get information about a recipient. It is accessed by GETing `get_user/{address}/{type}`; where type is one of the following:

* `public_key` - The most recent master public Ed25519 key (this should be checked each time a message is sent).
* `most_recent` - The most recent record for the user.
* `history` - The full history for the user.

On the first request a client makes for a specific user’s information, the full history should be requested so that the client can validate the signatures and hash chain. On subsequent requests the client need only request the public key and validate that it hasn’t changed. If a change is detected, the full history should be pulled and revalidated. 

The public key in the original record, and the most recent public key in the first request for a user’s information must be permanently stored to detect if a user’s history is being truncated or replaced in its entirety. If either of these conditions are detected, the client must not send messages to the user.

A client may request a user’s most recent information at any time to ensure they present current information to the user.

Each record shall contain fields for the following data, those followed by an asterisk are required to have a value:

* SMIMP Address*
* Public Key (Ed25519)*
* Signed hash of last change*
* Name
* Web Site URL
* Profiles (an optional list of social media profiles the user claims is theirs)
* Additional Data (an optional JSON document with user controlled fields)
* Date of change - Timestamp of when the change was made (`YYYY-MM-DD hh:mm:ss`); the time will be in UTC. Example: `2014-07-16 19:20:30`

The document above will be wrapped in another JSON document with two fields; `data` (which will contain the above document), and the signed hash (`signed_hash`), which will be the hash of the `data` field, signed by the user's Ed25519 key.

The hash must be signed with the Ed25519 key specified in the previous change record (except for the initial entry in the chain).

If the hash or signature fail to validated, the data must be discarded.

See `update_profile` for more information.

#### Get User Avatar (Optional)
The `user_avatar` API returns the user supplied JPG or PNG file that can be displayed by the client. It is called by the client by GETing `user_avatar/{address}`; the server will respond with a JSON document with two fields; the URL where the file can be found (must be over HTTPS), and the file hash, signed with the user’s master private Ed25519 key, to confirm that the user in question uploaded the image.

The file path provided may be temporary or protected from hotlinking; callers should cache the file and its hash. On subsequent calls, the hash can be compared, and the file will only need to be updated if the hash has changed.

Sample:
`https://smimp.example.com/0.1/get_user_avatar/adam%23example.com`

If the hash or signature isn’t valid, the image must be discarded.

### Session Management

#### Create Session (Required)

To login to perform authenticated actions, there will be two calls to the create_session API, the first being a `GET` to `create_session/{user-address}`, which will return a JSON document including a unique token (nonce), the second is a POST to `create_session/{user-address}` containing the token from the `GET` signed by the user’s master private Ed25519 key. The unsigned login token should not be used as a session ID or other sensitive value, as its hash will be exposed in messages sent.

If login was successful, an authentication token will be returned. The token should be placed in the `SMIMP-Authentication` HTTP header that must be sent in all authenticated API calls. The server will check the value of this header, and validate it on each call. If the login fails, an appropriate HTTP status code (and optionally an error message) will be returned.

This is used for both local users that have an account on the server, and remote users that wish to send a message or perform other privileged operations. This allows the server to monitor for abuse (ephemeral key depletion, etc.), and take action if appropriate. When a remote user connects, the server will request their public Ed25519 key from the appropriate server, when they send the `POST` with the signed token.

This way, the user is authenticated without the need for a password, just their private key.

#### Destroy Session (Required)

When the user has completed their work with the server, they should call the `destroy_session` API. This will be an empty `POST`, the server will determine the session from the authentication header. The session specified by the header must be ended on the server, so that if any further requests are received with that header, the requests fail with an authentication error.

### Sending A Message

#### Get Message Key (Required)

The `get_message_key` API is used to get the ephemeral or non-ephemeral public `curve25519xsalsa20poly1305` key used to encrypt the message. It is accessed by POSTing a JSON document containing the address of the recipient. The response will include a JSON document containing the user’s most recent public key, and the public key that should be used to encrypt the message, and a flag to indicate if the key is non-ephemeral.

The flag indicating if the key is non-ephemeral is included so that a client may queue the message and check again later for an ephemeral key if the user so desires. This will not be necessary (or advisable) for most users, but may be useful for users that need additional security.

The message key will be a public `curve25519xsalsa20poly1305` key signed by the user’s master private Ed25519 key. The server will return an unissued ephemeral key; if no ephemeral keys are available, the user’s non-ephemeral key will be sent. The non-ephemeral key may be changed at any time, so should not be stored. Senders should never attempt to encrypt messages with the user’s master public key; as it’s for signing only; the server must reject any message that lists the user’s master public key as the public key used to encrypt the message.

The requestor must be logged in to to access this API.

#### Get Proof of Work Parameters (Optional)

The `get_pow_params` API returns the parameters used to generate the proof of work value needed to send a message. It’s called by sending a `GET` to `get_pow_params/{address}/{message_type}`; this allows the server to dynamically adjust the work level based on recipient, sender, message type, or other factors. The nonce provided can only be used once, and is invalidated at the end of the session if not used.

The proof of work is calculated in a hashcash style partial hash collision, based on the following values; zero bits and nonce are provided by the `get_pow_params` API:

* Hash of login token
* Hash of Message field to be sent
* Recipient’s address
* Message Type
* Nonce (32 bytes)

The sender will concatenate the above fields, and a 32 byte value that will be generated to create the partial collision. The client will hash all of the values, and check to see if the `zero_bits` of most significant bits of the resulting hash are zero; if yes then the proof of work is generated, if not, a different value will be selected, and the process repeated until successful. 

The server may return a `zero_bits` value of 0, is which case, any value is accepted. This occurs when the sending address is whitelisted.

#### Send Message (Required)

The `send_message` API is used to send a user on the local system a message. It is called by POSTing a JSON document to `send_message/{address}`, the document (known hereafter as the envelope) must contain the following:

* Message - An encrypted JSON document, encrypted with the message key retrieved from `get_message_key`.
* Message Type - The type of message the client should expect (see below).
* Algorithm - The algorithm used to encrypt the message; currently `curve25519xsalsa20poly1305`.
* Message Public Key - The public key used to encrypt the message; must not be the recipient’s master public key. This is passed so that the recipient knows what key to use to decrypt the message.
* Nonce - The nonce used in encrypting the message.
* Proof of Work - The proof of work value (`{hash}:{value}:{nonce}`, in hex), based on the `get_pow_params` values; see get_pow_params for more details. The server must verify the solution, and that the nonce was issued in the sender’s current session, that it hasn’t been used in the session, and that it was issued for the recipient's address. This may be null if the server doesn’t implement the POW APIs.
* Message Hash - Hash the the encrypted message, message type, algorithm, recipient's public message key, proof of work value, nonce, and the hash of the session nonce provided on login. The hash must be signed by the sender’s master private key.

The server will add the following to the envelope when saving for later access by the client:

* Recipient's address
* Sender Address
* Sender Public Key - This should be verified from the user’s history before decrypting the message (to detect malicious server activity).
* Time Received
* Proof of Work Parameters
* Message ID - A unique value generated by the server, 32 bytes; may generate a random value, and hash it to reduce exposure of random values, in case of future issues with the PRNG leaking state. Hex encoded.
* Hash of Logon Token - To allow the recipient to independently confirm the signed hash; used as an anti-replay mechanism. Hex encoded.
* Received Via - How the passage was received, such as `smimp_client`, `smtp_bridge`, `imap_bridge`, `import_api` - this allows clients to determine how a message made it into the system, which may impact how messages are display, and how signing is validated.
* Read - true if the message has been read, otherwise false.
* Extensions Data - This is an encrypted JSON document containing key-value pairs, for messaging client extensions. This allows additional data to be passed without protocol modifications, allowing the industry quickly evolve functionality (example: reminders, etc.). The client is able to update this field as needed, unlike the one sent as part of the message field. This field defaults to null.
* Protocol Version - Currently `0.1`

To perform decryption, the client must convert the sender's public key from a Ed25519 key, to a curve25519 key, via libsodium's `crypto_sign_ed25519_pk_to_curve25519` method. When sending a message, the sender must convert their master private key (Ed25519) to a curve25519 key, via the `crypto_sign_ed25519_sk_to_curve25519` method.

The client must validate that the signed hash is accurate, and that the message field is signed by the sender. If these checks fail, or if the public key sent in the envelope isn’t found for the sender, the decryption must be aborted and the user alerted that the message is invalid.

In case of an error, the server will return an appropriate error code, and message in the body. For successful sends, the server will respond with a 200 code, and the message ID (hex encoded) in the response body.

### Mailbox Management

### List Folders (Optional)

To list all folders, GET `folders/{message-type}`, will return a JSON document listing all folders for the message type (display name, folder name, parent folder name, message type). To display all folders, regardless of message type, omit the message type parameter.

#### Create Folder (Optional)

To create a folder, POST to the `folders` API, with a JSON document containing the display name of the folder (UTF8), the folder name (used in the URL, special characters removed), the folder name of the parent (null for root), and the message type. 

If a parent is specified, it must be for the same message type as the folder being created. The folder name must be unique within a message type. The folder name must be lowercase.

#### Rename Folder (Optional)

To rename a folder, POST to `folders/{folder-name}`, with a JSON document containing the display name of the folder (UTF8), the folder name (used in the URL, special characters removed), and the folder name of the parent (null for root). This can be used for moving folders, as well as renaming them.

If a parent is specified, it must be for the same message type as the folder being created. The folder name must be unique within a message type. The folder name must be lowercase.

#### List Messages (Required)

To get the messages in a folder, GET `folder/{message-type}/{folder-name}`. This will return a JSON document with the following information:

* Message ID
* Date received
* Read status
* From address
* Envelope size in bytes

Clients can use the Message ID with the message API to get the envelope. If folder-name is not specified, the API will return the messages in the the root folder (likely to be displayed as "Inbox" for most clients).

#### Get Message (Required)

To retrieve a message, GET `message/{message-id}/{update_read}`, this will return the JSON envelope, as discussed in send_message. If `{update_read}` is false, then no change is made to the read status for the message, otherwise the message is marked as read. Implementors should be cautious with how they use the `{update_read}` flag, as it can lead to confusing behavior.

#### Move Message (Optional)

To move a message, POST to `message_move/{message-id}` with a JSON document that includes the `folder-name` of the folder the message should be moved to. A message can not be moved to a folder setup for a different message type.

#### Delete Message (Optional)

To delete a message from the server, DELETE `message/{message-id}`. There is no concept of "trash" or other place that deleted messages are moved to. Clients may create such functionality by creating a Trash folder and moving the message to that folder, and then performing the delete automatically later.

#### Get Message Read Status (Required)

To determine if a message has been read, GET `message_read/{message_id}`, this will return true for messages that have been read, otherwise false.

#### Update Message Read Status (Required)

To change the message read status, POST either true or false to `message_read/{message_id}`.

#### Update Message Extensions Data (Optional)

To update the extensions data stored in the envelope of a message (the extensions data in the encrypted message field is immutable), POST to `message_extensions/{message_id}` with the replacement encrypted JSON document.

### Account Administration

#### Initialize Account (Required)

When an account is created on the server, it doesn’t have enough information to accept messages or return identity data. To become usable, the account must be initialized by the client; setting core values needed to operate.

The `initialize_account` API accepts a JSON document similar to what’s used by `update_profile`, except that the hash doesn’t include the hash of the prior change (as there isn’t one), and the hash is signed by the new master private Ed25519 key that matches the public key being set. The JSON document also will contain the hash of a password specified when the account was created, the public encryption key, the non-ephemeral key, and an array of ephemeral keys (may be null).

This API uses a different authentication mechanism than other privileged calls, as at the time of use the user’s record doesn’t have a master key associated with it. As such, the user will pass a password to authenticate to the server - this is the only API that will use this password, and it can only be called once.

The server must not allow an account to be initialized more than once - as doing so would cause a data loss, and a breaking of all trust relationships.

#### Get / Set Non-Ephemeral Key (Required)

The `nonephemeral_key` API is used to get or replace the non-ephemeral key. GET `nonephemeral_key` returns the key, to replace the existing value, POST to `nonephemeral_key` with a JSON document containing the new key.

This is a public key signed by the user’s master private Ed25519 key, and is provided to senders if ephemeral keys are exhausted.

#### List Ephemeral Keys (Required)

A GET on `ephemeral_keys` will return a JSON document with an array of ephemeral keys that haven’t been issued as of the time of the call. Keys may be issued after the call completes.

#### Setting Ephemeral Keys (Required)

To replace the current set of ephemeral keys, POST a JSON document with an array of keys to `ephemeral_keys`. This operation replaces all keys not yet issued.

Care should be taken when setting keys based on those returned from a GET on `ephemeral_keys`; as if a key is issued to a sender after the call, a key may be used twice. This technique does have value though, as it can be used to extend the list of keys available, without wasting the space associated with storing the private keys.

Private keys for discarded public keys should be retained for some time, in case they were issued and a message sent with them. It’s the responsibility of the client to manage these keys.

#### Update Profile or Master Public Keys (Required)

The `update_profile` API can be used to update any of the profile fields (see `get_user` for more details). The client should send a JSON document with the value for all fields, the values specified will replace all values in the profile.

The can be used to update simple things, like the user’s web site, or to update the master key.

Each field will be included in a hash, as well as the signed hash from the last update; the hash will then be signed with the master private key that matches the prior record.

#### Update Avatar (Optional)

To set or update the user’s avatar, POST to `user_avatar` with a JSON document containing the image file, Base64 encoded, and the file hash signed with the user’s master private Ed25519 key.

#### Add Whitelist Entry (Optional)

To add a new address to the `whitelist`, POST to whitelist, passing in the following:

* Hash of the address or domain
* Encrypted JSON document with the address or domain, and a note - this is not used by the server, but is used to provide client with a viewable form of the data.

Entries in the whitelist override entries in the blacklist, address level entries override domain level entries. So it’s possible to apply a blacklist to `example.com`, but allow messages from `adam#example.com` from the whitelist.

It is not possible to update the note on an entry, to perform this, delete the entry and re-add.

The address or domain is hashed to provide additional privacy for the user; while it’s not ideal as it could be bruteforced, it decreases the usefulness of the data the server stores.

#### Remove Whitelist Entry (Optional)

To remove an entry from the whitelist, DELETE `whitelist/{hash}`, where hash is the hash of the address or domain.

#### Add Blacklist Entry (Optional)

To add a new address to the `blacklist`, POST to blacklist, passing in the following:

* Hash of the address or domain
* Encrypted JSON document with the address or domain, and a note - this is not used by the server, but is used to provide client with a viewable form of the data.

It is not possible to update the note on an entry, to perform this, delete the entry and re-add.

The address or domain is hashed to provide additional privacy for the user; while it’s not ideal as it could be bruteforced, it decreases the usefulness of the data the server stores.

#### Remove Blacklist Entry (Optional)

To remove an entry from the whitelist, DELETE `blacklist/{hash}`, where hash is the hash of the address or domain.

#### Quota (Optional)

The `quota` API is used to get the total size of all messages, and the total space available. Calling GET `quota` will return a JSON document with the above values. If space available is unlimited, the server should return -1.

### Message Types

These are the predefined message types that the send_message and related APIs handle. Closed loop systems may choose to only allow certain message types; public email-type servers MUST allow any message type.

Messages MUST never be sent in clear text, they must always be encrypted with a key retrieved via `get_message_key`. The message field in the envelope is immutable.

#### Email

For the the `email` message type, the message field is defined as a JSON document with the following fields.

* To - List of addresses that this message was sent to.
* Carbon Copy - List of addresses that were copied on this message.
* Subject - UTF8 string.
* Thread ID - If the first message in a thread, a unique value, if the message is a reply, the Thread ID from the message being replied to, 32 bytes; may generate a random value, and hash it to reduce exposure of random values, in case of future issues with the PRNG leaking state. Hex encoded.
* Reply To Message ID - If a reply, the Message ID of the message being replied to; if not a reply, null.
Date Sent - If a message is delayed for some reason, this may be different than the timestamp of when the server received the message. Shouldn’t be trusted, as could be set to an arbitrary value.
* Body - The body of the message, in Markdown format. No HTML / CSS / Javascript / etc. may be included. External content is rendered at the discretion of the recipient's client. UTF8.
* Signature Text - User's signature; Markdown, UTF8.
* Attachments - An array of JSON documents containing the file name and Base64 encoded file content.
* Extensions Data - This is a JSON document containing key-value pairs, for messaging client extensions. This allows additional data to be passed without protocol modifications, allowing the industry quickly evolve functionality. The client isn’t required to use, or even parse this field.
* Reply To - Address sender requests replies be sent to. May be null; if not null, must be a valid SMIMP address.
* Auto-Reply Address - Address that must be used when recipient generated errors or notifications (out of office, etc.). Must be at the same domain as the sender. 

#### Short Message

The `short-message` type is to allow text-message (SMS/MMS) type uses. This is a JSON document containing a message field, and an attachments field, containing an array of JSON documents containing the file name and Base64 encoded file content.

#### Secret Keypair - Ed25519

The `secret-ed25519` message type is to send a user a signing keypair. This is used to transfer / share ownership of an account, alias, or mailing list. When received, the key should be imported to the user’s keystore.

#### Secret Keypair - Curve25519 / XSalsa20 / Poly1305

The `secret-curve25519` message type is used to send the user a keypair used to decrypt a message or messages. The keypair may be for ephemeral or non-ephemeral use. When received, the keypair should be imported to the user’s keystore for future use.

#### Secret Key - XSalsa20 / Poly1305

The `secret-xsalsa20` message type is used to send a user a symmetric encryption key. When received, the key should be imported to the user’s keystore for future use.

#### Custom Messages

`x-custom-*` - This is for applications, or other systems to use to send messages meant for specific use. These messages should be ignored by clients intended for humans. These messages may be raw binary data, JSON, XML, etc. - and thus should only be handled by clients specifically designed for the message type. Name can consist only of lowercase alpha, numbers, and dashes.

### Special Notes on Use Cases

This section discusses certain uses cases in the traditional email world, and how these cases can be handled with SMIMP. This section is not meant to override, or provide exceptions to the Specification, but to explain how the system can be used to achieve certain goals.

#### Hosted Services (webmail)

Webmail like services are still possible, in two scenarios: client-side crypto, and server-side crypto. These obviously provide different levels of security and functionality.

##### Server Side Crypto

In this scenario, all crypto is performed on the server, as is key management. In this case the master private key, and all other keys are controlled by the server, and may or may not be exposed to the user.

The service would be able to provide more functionality (search, etc.) that would be difficult to do when performing client-side crypto. This comes at the cost of control, and security. The server has full control, including the ability to change master keys, and read all mail sent and received.

##### Client Side Crypto

In this scenario, all crypto work is performed via Javascript or a browser plugin. The browser would also be responsible for key management. Some features would be difficult or impossible to implement in a performant way, such as search.

Key management in this scenario could be complicated, especially as users cross devices.

#### Compliance (HIPAA, Sarbanes–Oxley, etc.)

In use cases where email must be monitored, such as business environments that must comply with compliance requirements, a solution is to use SMIMP similar to the server-side webmail option. So that a central system controls the keys for all users, and users connect to that server when sending or receiving messages.

This central server could perform archiving, content inspection, or other operations similar to the email infrastructure used today.

For the purposes of this document, in a scenario like this, the client would be a central server that all users connect to. How users interact with such a server is beyond the scope of this document.

#### Local Proxy

To allow the use of legacy clients, it’s possible to build a local SMTP / IMAP server that wraps the functionality of SMIMP, and would perform all crypto in a similar manner to the central server in the Compliance scenario. While it’s recommend to use software designed for SMIMP, this could be an effective tool during migration.

#### Local & Remote Mail Storage

The protocol allows clients to store messages on the server, or locally. To support scenarios where the user uses multiple devices, it’s recommended that most users keep their messages on the server. In high security situation, where the user only uses a single device - keeping messages locally will reduce the amount of data held on the server that could be available to third-parties.

#### Closed-Loop Systems

This system may be implemented in a more limited form for use by a single service, without having to worry about some more advanced functionality. This allow messaging applications, and similar systems to use a standard protocol for their backend infrastructure, but without allowing external users to authenticate to the server.

In these cases, all users will be on the same domain, and messages will only be exchanged between users of the single server - no messages coming in from external users, or going out of the system to external users. In such systems, users need not be aware that SMIMP is the underlying system powering the service or application.

#### User Authentication

Web sites and other services can use this infrastructure to authenticate users, by having them sign a token with their master Ed25519 key, and the service validates the signature. This way the service doesn’t need to store the user’s password hash, reducing the value of data lost in a breach.

This should be implemented as a browser extension.

### Explanation of Design Decisions

This section discusses various decisions made during the design process, and why those decisions were made.

#### HTTPS Transport Layer

Using HTTPS has a transport layer, instead of a new custom transport layer was done to achieve the following goals:

* Reduced Attack Surface - Well tested HTTP servers and libraries are readily available, by not introducing a new on the wire protocol, we are able to leverage the work and research that has went into the HTTP infrastructure.
* Firewall Friendliness - Port 443 (HTTPS) is one of the most likely ports to be open on a network, thus this can be used in many environments with minimal changes. This allows more users to take advantage of this system without the need to receive approval.
* Anti-Filtering - From ISPs, to national security agencies, SMTP is widely monitored or filtered. By sitting on top of HTTPS as a transport layer, such activities become much more complex. To gain even basic metadata, an attacker would have to perform a man in the middle attack, which HTTPS (via TLS) provides some degree of protection against.
* Ease of Implementation - Using HTTPS as a transport layer reduces the work needed to implement this protocol, allowing developers to spend more time of usability and other issues, and reducing the amount of code requiring a detailed security review.

This approach also allows us to avoid some issues that we would have to address otherwise, such as whether to use TLS, or a simpler TLS-like protocol to provide protection to the data on the wire. It also avoids discussion of how to handle server authentication (using the existing CA infrastructure, or something else. While the current CA infrastructure is far from ideal, trying to address these issues would serve to complicate implementation, slow the public review process, and possibly make the protocol seem too “radical” for corporate environments. While it’s possible we could provide better security by addressing the CA issue here, the delays and possible controversy would prolong the harm being done to the public by traditional email.

#### Single SMIMP Server per Domain

As defined, the `\.well-known\smimp.txt` file contains only a single server. This could be modified to support multiple servers, but it’s believed that this is shifting an infrastructure problem to the client. 

Today, the issues with load balancing, geo-distributing servers, and redundancy are all easily addressed with existing technology - especially in the HTTPS space. As such, the burden of dealing with a down server is that of the server infrastructure. The client should still queue messages that can’t be delivered, but in general, the server infrastructure should handle issues transparently as is done with most large web sites.

#### The Non-Ephemeral Key

It is required that there be a special purpose key that the server can distribute when the supply of ephemeral keys is exhausted. It is a plausible attack that someone will intentionally exhaust the supply of ephemeral keys without sending any messages to force the use of a default key. If there is no default key, an attacker will be able to perform a denial of service attack by exhausting the ephemeral keys.

To prevent that default key from being the master key, the non-ephemeral key is introduced. This way, if the master key - and only the master key is compromised, it will still provide protection for older messages. If the default key was the master key, an attacker could continuously deplete the supply of ephemeral keys in hopes of later compromising the master key and decrypting most, if not all messages.

With this in mind, it’s likely that is the master private key was compromised, the keystore containing the other keys would likely be compromised as well. It’s the goal of this system to provide as much protection as possible - if the keystore is properly protected or destroyed, even if a target is coerced into providing the master private key, that may not provide access to historical messages.

#### Use of libsodium For Crypto

The number one rule when it comes to crypto in secure applications is don’t roll your own. In an application like this, that’s true for a few reasons:

* Compatibility - By using the same library in all implementations, it’s guaranteed that each message will encrypt the same way - this reduces the time needed for testing, and reduces the likelihood of inter-system compatibility issues.
* Development Time - By taking the crypto algorithms out of the development scope, development and testing time is reduced. This means that implementations can be in the hands of the public sooner.
* Auditability - Auditing individual implementations is easier when all the crypto work is in an standard library that’s already be widely reviewed.
* Safety & Trust - There is less chance of crypto related failures, and it’s easier to make people understand the security level provided, when using a single, well known library in all implementations.

The largest issue with this decision for some, will also be the greatest benefit for others - non-NIST crypto. The crypto used in libsodium isn’t approved or developed by NIST, and thus may not be suitable for certain environments. For others, NIST crypto is now looked at with distrust, and thus this can be seen as a good thing.

It could be argued that a NIST approvable mode would be advisable to achieve wide scale deployment. The decision may be made to this at some point, but for the initial release of this specification, that introduces unnecessary complexity to the implementations and for many adds a layer of distrust due to uncertainty around NIST and their motivations.

While we strongly encourage implementers to use libsodium, if one choses to use their own, or a competing implementation, that’s their right, so long as it’s compatible. The goal is to achieve a viable email replacement, not to provoke religious wars around crypto libraries. In the future, it may be reasonable to recommend a different, compatible library; nothing in this document prevents that.

#### Use of Markdown for Message Body

The use of HTML is too dangerous for a messaging system designed to be secure - too many times in the past has simply viewing a message allowed a machine to be exploited. There are many libraries for Markdown, both viewing and editing - so users will be able to use Markdown directly, or be able to use a WYSIWYG editor. The attack surface for Markdown is much smaller than HTML, and thus should be safer.

It’s felt that this is the best option to provide flexibility and security.

This applies only to the email message type. This will likely be opposed by email marking interests, as it makes the highly formatting messages that exist today in the email space impossible, but from the perspective of the authors of this specification, security trumps formatting.

#### JSON Canonicalization

Including JSON documents in hashes should be avoided when possible, due to differences in formatting. Different JSON libraries produce JSON that can vary in whitespace, order, and other formatting - as such, care must be taken to avoid allowing a difference in library, or even library version to introduce a breaking change.

Based on the issues found by others trying to canonicalize JSON, that will be beyond the scope of this project. Either the values in the document should be hashed, or the document should be treated as a string literal and hashed as such - without any processing by a JSON library.

This document will not attempt to force a specific format for JSON.

#### Account Initialization

When the account is created on the server, there is additional data required, that isn’t easily specified by a human. We are solving this with the `initialize_account` API that sets all of the records needed to make the system work. Unfortunately, as this call has to be authenticated somehow, and the user doesn’t have a master key set - we have to use a password to authenticate the API call, the only place in the system that a password is used.

It’s possible to modify the design to require the master key to be provided manually when the account is created, and eliminate the need for the password, though this may introduce an undesirable usability issue.

#### No Trash on Deletion

While moving a message to a trash folder instead of actually deleting a message is a common practice, this can be harmful from a privacy perspective. At this time, it’s felt that the server should not implement such functionality, to prevent users from thinking they deleted a message, only to have it remain on the server.

Clients may implement this themselves, if they feel it is appropriate, but as a privacy oriented specification - it will not be included here.

#### Message Encryption Key Change

The server will not allow users to re-encrypt messages with a different key, to avoid tampering with messages.

#### Selected Crypto Algorithms

The following algorithms are in use as of the current version:

* Signing - Ed25519 (crypto_sign). Keys must not be deterministically generated (based off a user’s password for example).
* Public Key Encryption - Curve25519 / XSalsa20 / Poly1305 (crypto_box). Keys must be randomly generated, and public keys signed by the user’s signing key.
* Secret Key Encryption - XSalsa20 / Poly1305 (crypto_secretbox). Keys and nonces must be randomly generated.
* Hashing - Blake2b (crypto_generichash). No key, with 32 bytes of output. Blake2b has been chosen for its security and speed properties.

These are well reviewed, and implemented in a trustworthy manner in libsodium. 

It could be argued that using a single algorithm for each of these introduces a possible weakness if a flaw was detected in one of them, which is a valid point. Though, it could also be argued that trying to add some type of negotiation to determine what algorithms both sides speak could add undue complication. This may change in future versions, but at this time, this is believed to be the best answer for this protocol.

#### Crypto Algorithms & Future Versions

The algorithms used are tied to the API version, if the decision is to use other algorithms in future versions, a change in version number will be required, so that clients know what to use for that specific version.

In the future, a "preferred encryption algorithm" field may be added to allow clients to set one or more preferences that senders are asked to respect when encrypting messages. For now, this will be avoided for simplicity. This may be unavoidable in the future.

#### Address Local Part Format

It would be good to support any UTF8 string, with only a few blacklisted characters such as space as a valid local part, but it increases the complexity of validating the addresses. One goal here is to simplify the rules for what’s a valid local part compared to traditional email. 

As such, for now at least, the local part is restricted to `[alphanum]`; this decision is open for discussion. A better solution, that achieves simple parsing and validation, and giving more flexibility for users of languages other than English would be ideal and welcome.
