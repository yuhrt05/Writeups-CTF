# JerseyCTF 2026

![Social_Logo](https://hackmd.io/_uploads/Hk3qx2vpWl.png)

## Galaga Archive

![image](https://hackmd.io/_uploads/BJr8G0-6-x.png)

Export các file được truyền bằng SMB nhận được 4 file txt, trong đó có 1 file là hướng dẫn tạo khóa để XOR decrypt 2 file ideas

Khóa: SHA256(password)

![image](https://hackmd.io/_uploads/r1KH4iUTZg.png)

Thấy được có các giao thức liên quan đến xác thực Active Directory  qua kerberos như `AS-REQ`, `AS-REP`, `TGS-REP` và tương ứng với nó cũng có các kỹ thuật để tấn công như sau :

- AS-REQ Attack (Kerberos Pre-authentication)
    - Điều kiện: Tài khoản bật Kerberos Pre-authentication, Attacker bắt được lưu lượng mạng hoặc đang brute-force mật khẩu
    - Cơ chế: Khi người dùng đăng nhập, client gửi bản tin AS-REQ chứa timestamp đã được mã hóa bằng key sinh từ mật khẩu.
        - Nếu attacker thu được gói tin này, có thể đem dữ liệu mã hóa đó đi brute-force offline bằng: Hashcat, John the Ripper
- AS-REP Roasting (No Pre-auth):
    - Mục đích: Tấn công các tài khoản được cấu hình "Do not require Kerberos preauthentication".
    - Cơ chế: Nếu pre-auth bị tắt, KDC sẽ trả về AS-REP ngay lập tức, trong đó chứa dữ liệu được mã hóa bằng hash từ mật khẩu người dùng.
        - Attacker chỉ cần yêu cầu AS-REP rồi crack offline.

=> Đây là kỹ thuật được sử dụng trong bài này.
- TGS-REP (Kerberoasting)
    - Mục đích: Tấn công Service Account
    - Cơ chế: Bất kỳ user nào trong domain cũng có thể yêu cầu TGS ticket cho một SPN. Ticket này được mã hóa bằng mật khẩu của service account. Sau đó attacker trích xuất hash và brute-force offline.

Trước đây thì phải extract thủ công bằng tay từng trường thông tin để tạo ra hash đem bruteforce nhưng hôm đó làm tự nhiên mình search được repo [TẠI ĐÂY](https://github.com/jalvarezz13/Krb5RoastParser/blob/main/krb5_roast_parser.py) khá hay nó gộp hết cả 3 loại tấn công kia luôn, rất yêu <3

Git clone về rồi chạy tool thôi

![image](https://hackmd.io/_uploads/rk1WOsITbl.png)

Dùng `hashcat -m 18200 <hashfile> <wordlist>` để crack

![image](https://hackmd.io/_uploads/Hys9Os8Tbg.png)

=> password là `galagalogz`

```python
import hashlib
import binascii
import sys
input_file = "ideas1.txt"  
password = "galagalogz" 
def decrypt():
    key = hashlib.sha256(password.encode()).digest()
    try:
        with open(input_file, 'r') as f:
            hex_content = f.read().strip()
        ciphertext = binascii.unhexlify(hex_content)
        decrypted = bytearray()
        for i in range(len(ciphertext)):
            decrypted.append(ciphertext[i] ^ key[i % len(key)])
        print(decrypted.decode('utf-8', errors='replace'))
    except Exception as e:
        print(f"Error{e}")
if __name__ == "__main__":
    decrypt()
```

![image](https://hackmd.io/_uploads/Ska0tj8a-l.png)

Flag: `jctf{roasted_galatic_invaders}`

## file-transfer

![image](https://hackmd.io/_uploads/By8HGRbpZg.png)

Bài này vẫn dùng SMB để truyền file nhưng ngoài SMB2 thì có thêm SMB3. Điểm khác biệt lớn nhất giữa SMB2 và SMB3 là tính năng Protocol-level Encryption (AES-CCM/GCM).
- Vấn đề: Khi quan sát các gói tin SMB2_COM_WRITE hoặc SMB2_COM_READ trên Wireshark, toàn bộ phần dữ liệu sẽ hiển thị dưới dạng Encrypted SMB3.
- Giải pháp: Tuy dữ liệu bị mã hóa, nhưng quá trình Handshake để thiết lập phiên làm việc vẫn diễn ra theo cơ chế Challenge-Response. Chúng ta sẽ khai thác sơ hở trong giao thức xác thực yếu này để tìm mật khẩu dạng plaintext của người dùng.

Hướng đi sẽ là crack NTLMv2 Hash trong file pcap

Mục tiêu cốt lõi là thu thập đủ 5 thành phần định danh từ lưu lượng mạng (Pcap) để đưa vào crack:
- Identity: User name & Domain.
- Salt: Server Challenge (8 bytes).
- Digest: NTProofStr (16 bytes).
- Blob: Modified NTLMv2 Response (Dữ liệu bổ trợ chứa Client Nonce, Timestamp và cấu trúc Target Info).

Cấu trúc: `username::domain:ServerChallenge:NTproofstring:modifiedntlmv2response`

Tìm đến gói tin `NTLMSSP_AUTH` và `NTLMSSP_CHALLENGE` để trích xuất đủ thông tin

![image](https://hackmd.io/_uploads/Byn86oU6-g.png)

=> hash: 
```
operator1::IT640:a83c46425815db34:e705d3efd451d9eff0b3005233f7b573:010100
00000000001366cc6ceecddc012eec3d0097740ebd0000000002000a004900540036003400
3000010012005700530032003000320035002d00530031000400260063006f00720070002e
00690074003600340030002e0069006e007400650072006e0061006c0003003a0057005300
32003000320035002d00530031002e0063006f00720070002e00690074003600340030002e
0069006e007400650072006e0061006c000500260063006f00720070002e00690074003600
340030002e0069006e007400650072006e0061006c00070008001366cc6ceecddc01060004
00020000000800500050000000000000000000000000200000324ad49cd8c06cd57b3e895f
d7e1f8b498a54f8a43816223dfab71e7013c6ce0efb9d8a1f651758f475c106843bb63d662
2ba533b447ac1d4cb80299edea1f940a001000000000000000000000000000000000000900
1e0063006900660073002f00310030002e0031002e0032002e003200300030000000000000
000000
```

Tiến hành crack bằng hashcat: `hashcat -m 5600 crack.txt password.txt`

![image](https://hackmd.io/_uploads/BJlFjAoL6bl.png)

=> password: `password`

Dùng password này tiến hành decrypt SMB3 data

![image](https://hackmd.io/_uploads/Hy-MJnLTZe.png)

![image](https://hackmd.io/_uploads/BkV7yhL6bx.png)

Đã decrypt thành công, nhận được file `DaVinci.exe`, export về rồi tiến hành reverse

Hàm `sub_401300`

```cpp
int sub_401300()
{
  int Error; // eax
  int v2; // eax
  int v3; // eax
  ADDRINFOA pHints; // [esp+0h] [ebp-3C8h] BYREF
  int len; // [esp+20h] [ebp-3A8h]
  PADDRINFOA ppResult; // [esp+24h] [ebp-3A4h] BYREF
  PADDRINFOA i; // [esp+28h] [ebp-3A0h]
  int v8; // [esp+2Ch] [ebp-39Ch]
  SOCKET s; // [esp+30h] [ebp-398h]
  WSAData WSAData; // [esp+34h] [ebp-394h] BYREF
  char buf[512]; // [esp+1C4h] [ebp-204h] BYREF
  s = -1;
  sub_403590(buf, 0, 512);
  len = 512;
  ppResult = 0;
  i = 0;
  v8 = WSAStartup(0x202u, &WSAData);
  if ( v8 )
  {
    sub_401740("WSAStartup failed with error: %d\n", v8);
    return 1;
  }
  else
  {
    sub_403590(&pHints, 0, 32);
    pHints.ai_family = 0;
    pHints.ai_socktype = 1;
    pHints.ai_protocol = 6;
    v8 = getaddrinfo("10.1.2.211", "55544", &pHints, &ppResult);
    if ( v8 )
    {
      sub_401740("getaddrinfo failed with error: %d\n", v8);
      WSACleanup();
      return 1;
    }
    else
    {
      for ( i = ppResult; i; i = i->ai_next )
      {
        s = socket(i->ai_family, i->ai_socktype, i->ai_protocol);
        if ( s == -1 )
        {
          Error = WSAGetLastError();
          sub_401740("socket failed with error: %ld\n", Error);
          WSACleanup();
          return 1;
        }
        v8 = connect(s, i->ai_addr, i->ai_addrlen);
        if ( v8 != -1 )
          break;
        closesocket(s);
        s = -1;
      }
      freeaddrinfo(ppResult);
      if ( s == -1 )
      {
        sub_401740("Unable to connect to server!\n");
        WSACleanup();
        return 1;
      }
      else if ( sub_401000(s, ::buf) )
      {
        return 1;
      }
      else if ( sub_401180(s) )
      {
        return 1;
      }
      else if ( sub_401000(s, aCmdSeqB) )
      {
        return 1;
      }
      else if ( sub_401180(s) )
      {
        return 1;
      }
      else if ( sub_401000(s, aCmdSeqC) )
      {
        return 1;
      }
      else if ( sub_401180(s) )
      {
        return 1;
      }
      else if ( sub_401000(s, aCmdSeqD) )
      {
        return 1;
      }
      else if ( sub_401180(s) )
      {
        return 1;
      }
      else
      {
        v8 = shutdown(s, 1);
        if ( v8 == -1 )
        {
          v2 = WSAGetLastError();
          sub_401740("shutdown failed with error: %d\n", v2);
          closesocket(s);
          WSACleanup();
          return 1;
        }
        else
        {
          do
          {
            v8 = recv(s, buf, len, 0);
            if ( v8 <= 0 )
            {
              if ( v8 )
              {
                v3 = WSAGetLastError();
                sub_401740("recv failed with error: %d\n", v3);
              }
              else
              {
                sub_401740("Connection closed\n");
              }
            }
            else
            {
              sub_401740("Bytes received: %d\n", v8);
            }
          }
          while ( v8 > 0 );
          closesocket(s);
          WSACleanup();
          return 0;
        }
      }
    }
  }
}
```
Hàm `sub_401300` là một TCP Client thực hiện một kịch bản giao tiếp cố định tới địa chỉ `10.1.2.211:55544`. Nó không chỉ kết nối đơn thuần mà còn thực hiện một quy trình nghiệp vụ gồm 4 bước gửi lệnh liên tiếp, sau đó đợi nhận dữ liệu phản hồi cuối cùng trước khi ngắt kết nối hoàn toàn.

- `sub_401000`: Dựa vào tham số truyền vào (s, buf, aCmdSeqA, ...), hàm này đóng vai trò là hàm Send (Gửi dữ liệu).
- `sub_401180`: Đóng vai trò là hàm Receive/Acknowledge (Đợi phản hồi từ server)

![image](https://hackmd.io/_uploads/SJN1HBvpbe.png)

Hàm `sub_401180` nhận phản hồi từ server, thực hiện truyền vào hàm `sub_4010F0` để thực hiện decrypt
```
int __cdecl sub_401180(SOCKET s)
{
  int Error; // eax
  char *lpMem; // [esp+4h] [ebp-214h]
  char *v4; // [esp+8h] [ebp-210h]
  int v5; // [esp+Ch] [ebp-20Ch]
  int v6; // [esp+10h] [ebp-208h]
  char buf[512]; // [esp+14h] [ebp-204h] BYREF

  sub_403590(buf, 0, 512);
  v5 = 0;
  while ( 1 )
  {
    v6 = recv(s, &buf[v5], 512 - v5, 0);
    if ( v6 <= 0 )
      break;
    sub_401740("Bytes received: %d\n", v6);
    v5 = v6;
    v4 = (char *)sub_401070(buf, 512, &unk_4181F4, 3);
    if ( v4 )
      v6 = -1;
    if ( v6 <= 0 )
    {
      if ( v4 != buf )
      {
        lpMem = (char *)sub_4010F0(buf, v4 - buf);
        sub_401740("command: %s\n", lpMem);
        sub_405866(lpMem);
        sub_405730(lpMem);
      }
      return 0;
    }
  }
  if ( v6 )
  {
    Error = WSAGetLastError();
    sub_401740("recv failed with error: %d\n", Error);
  }
  return -1;
}
```

`sub_4010F0`
```
int __cdecl sub_4010F0(int a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-Ch]
  unsigned int i; // [esp+Ch] [ebp-8h]
  v3 = sub_405740(512);
  for ( i = 0; i < a2; ++i )
    *(_BYTE *)(i + v3) = aSorryImNotTheF[(int)i % 24] ^ *(_BYTE *)(i + a1);
  *(_BYTE *)(a2 + v3) = 0;
  return v3;
}
```

Đây chính là hàm giải mã dữ liệu sử dụng XOR với key xoay vòng, nội dung biến `aSorryImNotTheF`:

![image](https://hackmd.io/_uploads/S1LxUBD6-x.png)

Tiến hành viết script python để decrypt

```python
def xor_decrypt(ciphertext_hex, key):
    data = bytes.fromhex(ciphertext_hex)
    key = key.encode()
    decrypted = ""
    for i in range(len(data)):
        decrypted += chr(data[i] ^ key[i % len(key)])
    return decrypted
cipher_hex = """

""" 
key = "sorry_im_not_the_flag_:)"

print("Decrypted Message: ", xor_decrypt(cipher_hex, key))
```

![image](https://hackmd.io/_uploads/HyRADBDpWl.png)

FLAG: `jctf{Dah914znHQigIolS-j7xvL5XiYooM4Uce}`

## Saturn Colony

![image](https://hackmd.io/_uploads/rkH8MsLaWx.png)

Đề bài cung cấp mem, 1 file enc, và 1 file iv-hex. ta có thể dễ dàng đoán là phải đi tìm key trong mem để decrypt file enc

IV: `98ba2cc716d1e9fb865428b59fae7ead`

Nhận thấy tiếp IV đang là 16 byte => Khả năng cao mã hóa đang được sử dụng là AES-256 => Cần tìm KEY có 32 byte. Dựa thêm vào đề bài bảo cần tìm 5 fragments để ghép thành key đúng theo thứ tự:

`mecury -> venus -> earth -> mars -> jupiter`

=> Cần 4 mảnh 6 byte và 1 mảnh 8 byte

Check qua mem với psaux, nhận thấy có 5 tiến trình liên quan đến `fragment_service.py` và 1 tiến trình liên quan đến `jump_authorized`. 

![image](https://hackmd.io/_uploads/rJ08OtDabx.png)

Mình tiến hành check file python bằng pagecache.Files nhưng nhận thấy không hề có khả năng cao script này chỉ chạy trong ram. Còn đối với `jump_authorized` thì có xuất hiện, tiến hành dump em nó về

![image](https://hackmd.io/_uploads/Bykr9Ywp-x.png)

![image](https://hackmd.io/_uploads/HJo-jKw6-x.png)

Đem đi reverse thử thì nhận thấy đây là một file sinh fake key để đánh lạc hướng người chơi. Mục đích của tiến trình này là làm nhiễu dữ liệu trong RAM bằng cách liên tục sinh ra hàng nghìn chuỗi có cấu trúc giống hệt Key Fragment (ORION_FRAGMENT, JUMP_AUTH,...) thông qua /dev/urandom. Điều này khiến việc sử dụng lệnh strings trên toàn bộ file dump memory trở nên vô nghĩa vì lượng rác quá lớn.

```cpp
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v3; // ebx
  __pid_t v4; // eax
  unsigned __int64 v5; // r14
  int v6; // ebx
  FILE *v7; // rax
  FILE *v8; // rdi
  __int64 v9; // rax
  unsigned __int64 v10; // rdx
  __int64 v11; // rax
  unsigned __int64 v12; // rcx
  char *v13; // r15
  int v14; // r12d
  const char **v15; // r13
  int v16; // eax
  unsigned __int64 v17; // rdx
  unsigned __int64 v18; // rcx
  __int64 i; // rax
  __int16 v20; // cx
  _WORD *v21; // rax
  const char *v23; // [rsp+10h] [rbp-B8h]
  char *v24; // [rsp+18h] [rbp-B0h]
  int v25; // [rsp+20h] [rbp-A8h]
  int v26; // [rsp+24h] [rbp-A4h]
  char *v27; // [rsp+28h] [rbp-A0h]
  __m128i si128; // [rsp+40h] [rbp-88h]
  _BYTE v29[16]; // [rsp+50h] [rbp-78h] BYREF
  _WORD v30[20]; // [rsp+60h] [rbp-68h] BYREF
  unsigned __int64 v31; // [rsp+88h] [rbp-40h]
  v31 = __readfsqword(0x28u);
  v3 = time(0LL);
  v4 = getpid();
  srand(v3 ^ v4);
  v27 = (char *)calloc(0x1F400uLL, 1uLL);
  if ( v27 )
  {
    v26 = 500;
    v5 = 128000LL;
    v24 = v27;
    si128 = _mm_load_si128((const __m128i *)&xmmword_2290);
    while ( 1 )
    {
      v23 = (&off_3D00)[rand() % 10];
      v25 = rand() % 9 + 1;
      v6 = si128.m128i_i32[rand() % 4];
      v7 = fopen("/dev/urandom", "r");
      if ( !v7 )
        goto LABEL_6;
      v8 = v7;
      if ( v6 != _fread_chk(v29, 16LL, 1LL, v6, v7) )
        break;
      fclose(v8);
      if ( v6 <= 0 )
      {
        v21 = v30;
      }
      else
      {
        for ( i = 0LL; i != v6; v30[i++] = v20 )
        {
          LOBYTE(v20) = a0123456789abcd[(v29[i] >> 4) & 0xF];
          HIBYTE(v20) = a0123456789abcd[v29[i] & 0xF];
        }
        v21 = &v30[v6];
      }
      *(_BYTE *)v21 = 0;
LABEL_7:
      switch ( rand() % 5 )
      {
        case 0:
          LODWORD(v9) = _snprintf_chk(
                          v24,
                          128LL,
                          2LL,
                          v5,
                          "ORION_FRAGMENT::%s::%d/5::%s\n",
                          v23,
                          v25,
                          (const char *)v30);
          if ( (int)v9 < 0 )
            LODWORD(v9) = 0;
          v9 = (int)v9;
          v24 += (int)v9;
          break;
        case 1:
          LODWORD(v9) = _snprintf_chk(v24, 128LL, 2LL, v5, "ORION_KEY::%s::shard_%d::%s\n", v23, v25, (const char *)v30);
          if ( (int)v9 < 0 )
            LODWORD(v9) = 0;
          v9 = (int)v9;
          v24 += (int)v9;
          break;
        case 2:
          LODWORD(v9) = _snprintf_chk(v24, 128LL, 2LL, v5, "JUMP_AUTH::%s::fragment::%s\n", v23, (const char *)v30);
          if ( (int)v9 < 0 )
            LODWORD(v9) = 0;
          v9 = (int)v9;
          v24 += (int)v9;
          break;
        case 3:
          LODWORD(v9) = _snprintf_chk(v24, 128LL, 2LL, v5, "COLONY_DATA::%s::%d::%s\n", v23, v25, (const char *)v30);
          if ( (int)v9 < 0 )
            LODWORD(v9) = 0;
          v9 = (int)v9;
          v24 += (int)v9;
          break;
        case 4:
          LODWORD(v9) = _snprintf_chk(v24, 128LL, 2LL, v5, "NAV_SHARD::%s::%d/5::%s\n", v23, v25, (const char *)v30);
          if ( (int)v9 < 0 )
            LODWORD(v9) = 0;
          v9 = (int)v9;
          v24 += (int)v9;
          break;
        default:
          v9 = 0LL;
          break;
      }
      v10 = 128000LL;
      if ( v5 >= 0x1F400 )
        v10 = v5;
      v11 = v10 + v9;
      v12 = v11 - v5;
      if ( v11 - v5 < v10 )
        v12 = v10;
      v5 = v12 + v5 - v11;
      if ( !--v26 )
      {
        v13 = v24;
        v14 = 100;
        while ( 1 )
        {
          v15 = (const char **)off_3CC0;
          do
          {
            v16 = _snprintf_chk(v13, 128LL, 2LL, v5, "%s\n", *v15);
            if ( v16 < 0 )
              v16 = 0;
            v17 = 128000LL;
            if ( v5 >= 0x1F400 )
              v17 = v5;
            v18 = v16 + v17 - v5;
            if ( v18 < v17 )
              v18 = v17;
            ++v15;
            v13 += v16;
            v5 = v18 + v5 - (v16 + v17);
          }
          while ( v15 != (const char **)&unk_3CE8 );
          if ( !--v14 )
          {
            puts("jump_authorizer running (memory-only).");
            fflush(stdout);
            while ( 1 )
              sleep(2u);
          }
        }
      }
    }
    fclose(v8);
LABEL_6:
    LOBYTE(v30[0]) = 0;
    goto LABEL_7;
  }
  return 1LL;
} 
```

Ví dụ các fake key nhặt được trong ram:

![image](https://hackmd.io/_uploads/r1O0CcPTZg.png)


Nhận thấy không còn gì khai thác thêm ở tiến trình `jump_authorized`, vì vậy chỉ còn 1 hướng đi duy nhất là phân tích map của các PID liên quan đến `fragment_service.py` 

Dump hàng loạt vùng nhớ của 5 pid khác nhau về, strings riêng vùng nhớ     `heap` là nơi lưu trữ các biến động sinh ra trong quá trình script Python thực thi, nhận thấy được có các chuỗi lặp đi lặp lại hoàn toàn giống nhau nghi ngờ chính là `key`

![image](https://hackmd.io/_uploads/S1vreiPTWg.png)

![image](https://hackmd.io/_uploads/Hk6igsv6Zl.png)

Thấy được strings vẫn khó đọc, thực hiện thử bruteforce XOR với 0x00 -> 0xFF

![image](https://hackmd.io/_uploads/Sk_mMjDaZg.png)

Tại 0x5a thấy ra chuỗi có nghĩa, thực hiện lần lượt với 4 key còn lại

![image](https://hackmd.io/_uploads/r1V3Gov6Wx.png)

```
::mercury::1/5::6dd525b8fc4a
::venus::2/5::ab4d6005db12
::earth::3/5::511c133efbfd
::mars::4/5::e7d97c1dbde6
::jupiter::5/5::96be27b08985eb61
```

Thực hiện ghép 5 frag tạo key

KEY: `6dd525b8fc4aab4d6005db12511c133efbfde7d97c1dbde696be27b08985eb61`
![image](https://hackmd.io/_uploads/Bku2XowpZe.png)


## mars-dominion

![image](https://hackmd.io/_uploads/Hy2NQo8TWl.png)

Đọc log lấy từng mảnh 1 thôi ez, có tổng 5 mảnh
