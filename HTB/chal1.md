# _TRUE SECRETS_
Cùng mình giải quyết 1 bài được tag easy trong HTB nhé 🙉

![image](https://github.com/dxurt/CTF/blob/main/HTB/Screenshot%202025-01-15%20031111.png)

## _Solution_

Theo mô tả của bài _"...Fortunately, our unit was able to raid the home of the leader of the APT group and take a memory capture of his computer while it was still powered on..."_ thì mình đoán thử thách này liên quan đến **MEMORY DUMP**

Mình dùng **volatility3** với plugin là windows.pstree để xem các tiến trình

![image](https://github.com/user-attachments/assets/32788d97-7b8e-48e7-9d93-a28be500385c)

Xem qua một lượt thì mình thấy toàn những tiến trình quen thuộc của windows như **svchost.exe**, **expoler.exe**, ... và chúng đều không nằm ở các đường dẫn lạ

Lướt xuống cuối thì thấy 2 tiến trình khá lạ là *True Crypt.exe* và *7zFM.exe*

![image](https://github.com/user-attachments/assets/08611c37-7fe7-438f-91d3-b953a1bf096f)

Kết quả có vẻ khả quan hơn khi mình nhìn thấy có 2 file .zip

![image](https://github.com/user-attachments/assets/52433706-40a3-4f4e-be24-8d0ba85609c4)

Thử unzip 1 cái xem sao

![image](https://github.com/user-attachments/assets/dd83858b-63bb-4081-90e7-f8edb811f106)

Lần đầu mình nghe đến cái loại này, nhớ lại thì lúc nãy có làm việc với file True crypt.exe nên mình thấy cũng khá hợp lí

Và chat GPT cũng chỉ mình cách để làm việc với file đó luôn <3

![image](https://github.com/user-attachments/assets/f43ea845-502d-47c3-8581-e93bbac1ccbc)

Mình search gg VeraCrypt rồi tải về và đọc theo hướng dẫn của chat gpt tiếp thui

![image](https://github.com/user-attachments/assets/7771741c-ef4a-46f8-a3e0-f0ad9f0b78d9)

Đến đây thì cần pass :)) rồi mình mắc kẹt và sau nhiều thời gian trao đổi với con chat gpt thì mình cũng có được

![image](https://github.com/user-attachments/assets/3e4ff448-bbec-4243-9b2b-b871650cdefe)

Và đã có kết quả 

![image](https://github.com/user-attachments/assets/588f9296-e239-43c2-82c8-df9b0f70d8b3)

Mình nhập pass

![image](https://github.com/user-attachments/assets/7625d0a6-3645-43f2-b56b-fe5fea0c8ec0)

Nhưng phiên bản mình tải lại không hỗ trợ

![image](https://github.com/user-attachments/assets/debe148e-1c0f-4330-bf07-9b91f8f2e9b0)

Mình ngồi mày mò, sau một hồi thì thấy được 1 bài viết về TrueCrypt support

![image](https://github.com/user-attachments/assets/79158bc2-350f-4b34-a128-aee280efa3e1)

Ở bài viết trên có nói là chỉ hỗ trợ các phiên bản 1.0f nên mình tìm và cài lại phiên bản đó

![image](https://github.com/user-attachments/assets/25085a8d-0e0c-4d13-ad35-d16194489ca8)

Mở ổ đĩa mới tạo ra thì thấy có 1 file .cs và một folder seesion chứa 3 file. xem file .cs trước

![image](https://github.com/user-attachments/assets/543bb8dd-5b7c-42b2-a6c9-e1423bbb2f9a)

```C#
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;

class AgentServer {
  
    static void Main(String[] args)
    {
        var localPort = 40001;
        IPAddress localAddress = IPAddress.Any;
        TcpListener listener = new TcpListener(localAddress, localPort);
        listener.Start();
        Console.WriteLine("Waiting for remote connection from remote agents (infected machines)...");
    
        TcpClient client = listener.AcceptTcpClient();
        Console.WriteLine("Received remote connection");
        NetworkStream cStream = client.GetStream();
    
        string sessionID = Guid.NewGuid().ToString();
    
        while (true)
        {
            string cmd = Console.ReadLine();
            byte[] cmdBytes = Encoding.UTF8.GetBytes(cmd);
            cStream.Write(cmdBytes, 0, cmdBytes.Length);
            
            byte[] buffer = new byte[client.ReceiveBufferSize];
            int bytesRead = cStream.Read(buffer, 0, client.ReceiveBufferSize);
            string cmdOut = Encoding.ASCII.GetString(buffer, 0, bytesRead);
            
            string sessionFile = sessionID + ".log.enc";
            File.AppendAllText(@"sessions\" + sessionFile, 
                Encrypt(
                    "Cmd: " + cmd + Environment.NewLine + cmdOut
                ) + Environment.NewLine
            );
        }
    }
    
    private static string Encrypt(string pt)
    {
        string key = "AKaPdSgV";
        string iv = "QeThWmYq";
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] ivBytes = Encoding.UTF8.GetBytes(iv);
        byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(pt);
        
        using (DESCryptoServiceProvider dsp = new DESCryptoServiceProvider())
        {
            var mstr = new MemoryStream();
            var crystr = new CryptoStream(mstr, dsp.CreateEncryptor(keyBytes, ivBytes), CryptoStreamMode.Write);
            crystr.Write(inputBytes, 0, inputBytes.Length);
            crystr.FlushFinalBlock();
            return Convert.ToBase64String(mstr.ToArray());
        }
    }
}
```
Đọc qua thì có thể thấy đây là kiểu mã hóa DES với key và iv cho sẵn như ở trên

Với 3 file tiếp thì mình thấy những kí tự rất quen nhất là có dấu "=" :)) Khả năng là mã hóa base64

```
wENDQtzYcL3CKv0lnnJ4hk0JYvJVBMwTj7a4Plq8h68=
M35jHmvkY9WGlWdXo0ByOJrYhHmtC8O0rZ28CviPexkfHCFTfKUQVw==
hufGZi+isAzspq9AOs+sIwqijQL53yIJa5EVcXF3QLLwXPS1AejOWfPzJZ/wHQbBAIOxsJJIcFq0+83hkFcz+Jz9HAGl8oDianTHILnUlzl1oEc30scurf41lEg+KSu/6orcZQl3Bws=
6ySb2CBt+Z1SZ4GlB7/yL4cOS/j1whoSEqkyri0dj0juRpFBc4kqLw==
U2ltlIYcyGYnuh0P+ahTMe3t9e+TYxKwU+PGm/UsltpkanmBmWym5mDDqqQ14J/VSSgCRKXn/E+DKaxmNc9PpPOG1vZndmflMUnuTUzbiIdHBUAEOWMO8wVCufhanIdN56BhtczjrJS5HRvl9NwE/FNkLGZt6HQNSgDRzrpY0mseJHjTbkal6nh226f43X3ZihIF4sdLn7l766ZksE9JDASBi7qEotE7f0yxEbStNOZ1QPDchKVFkw==

```
Mình lên cyberchef rồi thực hiện lần lượt để decode, với key và iv khi decode DES là 

```
string key = "AKaPdSgV";
string iv = "QeThWmYq";
```
Mình decode cả 3 file thì thấy flag ở dòng cuối 🙈

![image](https://github.com/user-attachments/assets/132dd15e-ad82-4189-8329-ac8692bd1473)


```
FLAG: HTB{570r1ng_53cr37_1n_m3m0ry_15_n07_g00d}
```

