# Blackfeather

**Encoding pipeline reverser + deserialization payload factory.**

Takes a blob, peels all encoding layers automatically, identifies the underlying format, and suggests an exploit payload for the matching stack.

## What it does

```
INPUT (file or string)
   ↓
[1] Peel encoding layers (recursive: base64, hex, gzip, URL, HTML, unicode, hash detection)
   ↓
[2] Identify format (Java serial, PHP serial, Python pickle, Ruby marshal, .NET, file types)
   ↓
[3] Extract class names (for Java) and detect libraries (Apache Commons, Spring, etc)
   ↓
[4] Compute confidence score
   ↓
[5] Suggest a `generate` command with the right gadget chain
```

## Why it's different

Most deserialization tools expect you to know the format already. Blackfeather takes a **raw blob** and figures out:

- The full encoding pipeline (e.g., `base64(gzip(serialized))`)
- The raw format on the inside
- Which libraries are likely on the classpath
- Which gadget chain to try first

## Install

```bash
git clone https://github.com/N1ght-b1rd/Blackfeather.git
cd ~/Blackfeather
pip install -e .
```

## Usage

```bash
# Detect from string
blackfeather detect -d "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAAdwQAAAAAeA=="

# Detect from file
blackfeather detect -f blob.bin

# Pipe from stdin
cat payload.txt | blackfeather detect

# Skip encoding peel
blackfeather detect -d "aced0005..." --no-peel

# JSON output for piping
blackfeather detect -d "rO0AB..." --json
```

## Example output

```
 


                                         
            /'^`.        .-----------------                   
           /     \  __  /    ----------                     
          / /     \(  )/    -------                        
         //////   ` \/ `   -----                           
        //// / // :    : ----                             
       // / / /  /`    `--                               
      //         //`||`\\                                 
     //         VV'\||/'VV                         
    /            '//||\\`                                 
                 `'`''`'`                                 
     
                     ~ BLACKFEATHER Deserializer: v0.1.0 ~
                                -by N1ghtb1rd                                           

.........................................................................................................

[+] Input: 80 bytes -> "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAAAdwQAAAAAeA=="

[+] Encoding pipeline (outer -> inner):
  1. Base64  80 -> 58 bytes

[+] Peeled string: 
"\xac\xed\x00\x05sr\x00\x13java.util.ArrayListx\x81\xd2\x1d\x99\xc7a\x9d\x03\x00\x01I\x00\x04sizexp\x00\x
00\x00\x00w\x04\x00\x00\x00\x00x"

.........................................................................................................


╭───────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Format Identified.                                                                                    │
│   Java Serialization                                                                                  │
│                                                                                                       │
│     Confidence: 99%                                                                                   │
│     Magic: 0xaced0005                                                                                 │
│     Classes: java.util.ArrayList                                                                      │
│     Libraries: JDK (java.util.*)                                                                      │
╰───────────────────────────────────────────────────────────────────────────────────────────────────────╯

Generate Suggestion -- preview, not implemented yet:
  ?? blackfeather generate java:URLDNS --cmd "id"
    Test if deserialization fires (DNS only, no RCE)


```

## Supported encodings (peel)

| Encoder | Detects 
|---|---
| Hash (stop loop) | MD5, SHA-1, SHA-256, SHA-512 
| Gzip | magic 0x1F8B 
| Hex | even-length hex string 
| Base64 | standard + URL-safe 
| URL | %XX sequences 
| Unicode escape | `\uXXXX` 
| HTML entities | `&ent;` / `&#NN;` 

## Supported formats (identify)

| Format | Magic |
|---|---|
| Java Serialization | `0xACED0005` 
| Python Pickle | `0x80 0x02-0x05` 
| Ruby Marshal | `0x0408` 
| .NET BinaryFormatter | `0x00 0x01 0x00 ...` 
| PHP Serialization | regex `O:N:"..."` 
| PNG, JPEG, GIF, PDF, ZIP, ELF, BMP, XML, HTML | various 

## Roadmap

- [x] **Phase 1**: Core detect engine (peel + identify)
- [ ] **Phase 2**: Payload generation (ysoserial wrapper, native pickle)
- [ ] **Phase 3**: ???

