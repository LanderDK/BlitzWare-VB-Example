Imports System
Imports System.Threading

Namespace BlitzWare
    Module Module1
        Public BlitzWareAuth As New API(apiUrl:="https://api.blitzware.xyz/api",
                                         appName:="NAME",
                                         appSecret:="SECRET",
                                         appVersion:="VERSION")
        Sub Main()
            Console.WriteLine(vbCrLf & vbLf & "Connecting...")
            BlitzWareAuth.Initialize()
            Console.WriteLine("Connected!")

            Console.Write(vbCrLf & "[1] Login" & vbLf & "[2] Register" & vbLf & "[3] Upgrade" & vbLf & "[4] License key only" & vbLf & vbLf & "Choose option: ")

            Dim username, email, password, twoFactorCode, key As String

            Dim userOption As Integer = Integer.Parse(Console.ReadLine())
            Select Case userOption
                Case 1
                    Console.Write(vbCrLf & vbLf & "Enter username: ")
                    username = Console.ReadLine()
                    Console.Write(vbCrLf & vbLf & "Enter password: ")
                    password = Console.ReadLine()
                    Console.Write(vbCrLf & vbLf & "Enter 2FA (if enabled): ")
                    twoFactorCode = Console.ReadLine()
                    If Not BlitzWareAuth.Login(username, password, twoFactorCode) Then
                        Environment.Exit(0)
                    End If
                    BlitzWareAuth.Log("User logged in")
                Case 2
                    Console.Write(vbCrLf & vbLf & "Enter username: ")
                    username = Console.ReadLine()
                    Console.Write(vbCrLf & vbLf & "Enter password: ")
                    password = Console.ReadLine()
                    Console.Write(vbCrLf & vbLf & "Enter email: ")
                    email = Console.ReadLine()
                    Console.Write(vbCrLf & vbLf & "Enter license: ")
                    key = Console.ReadLine()
                    If Not BlitzWareAuth.Register(username, password, email, key) Then
                        Environment.Exit(0)
                    End If
                    BlitzWareAuth.Log("User registered")
                Case 3
                    Console.Write(vbCrLf & vbLf & "Enter username: ")
                    username = Console.ReadLine()
                    Console.Write(vbCrLf & vbLf & "Enter password: ")
                    password = Console.ReadLine()
                    Console.Write(vbCrLf & vbLf & "Enter license: ")
                    key = Console.ReadLine()
                    If Not BlitzWareAuth.Extend(username, password, key) Then
                        Environment.Exit(0)
                    End If
                    BlitzWareAuth.Log("User extended")
                Case 4
                    Console.Write(vbCrLf & vbLf & "Enter license: ")
                    key = Console.ReadLine()
                    If Not BlitzWareAuth.LoginLicenseOnly(key) Then
                        Environment.Exit(0)
                    End If
                    BlitzWareAuth.Log("User login with license")
                Case Else
                    Console.WriteLine(vbCrLf & vbLf & "Invalid Selection")
                    Thread.Sleep(3000)
                    Environment.Exit(0)
            End Select

            Console.WriteLine(vbCrLf & "User data:")
            Console.WriteLine("Username: " & BlitzWareAuth.uData.Username)
            Console.WriteLine("Email: " & BlitzWareAuth.uData.Email)
            Console.WriteLine("IP-address: " & BlitzWareAuth.uData.LastIP)
            Console.WriteLine("Hardware-Id: " & BlitzWareAuth.uData.HWID)
            Console.WriteLine("Last login: " & BlitzWareAuth.uData.LastLogin)
            Console.WriteLine("Subscription expiry: " & BlitzWareAuth.uData.ExpiryDate)

            'BlitzWareAuth.DownloadFile("fdf07f63-af97-4813-b025-2cfc9638ce23")

            Console.WriteLine(vbCrLf & "Closing in five seconds...")
            Thread.Sleep(5000)
            Environment.Exit(0)
        End Sub
    End Module
End Namespace