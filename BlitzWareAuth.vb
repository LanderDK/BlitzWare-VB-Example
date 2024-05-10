Imports System
Imports System.Security.Cryptography
Imports System.Text
Imports System.Net
Imports System.IO
Imports System.Diagnostics
Imports System.Net.Http
Imports System.Net.Http.Headers
Imports System.Web.Script.Serialization
Imports System.Linq
Imports System.Threading
Imports System.Text.RegularExpressions

Namespace BlitzWare
    Class Security
        Public Shared Function CalculateResponseHash(data As String) As String
            Using sha256Hash As SHA256 = SHA256.Create()
                Dim bytes As Byte() = Encoding.UTF8.GetBytes(data)
                Dim hashBytes As Byte() = sha256Hash.ComputeHash(bytes)
                Return BitConverter.ToString(hashBytes).Replace("-", "").ToLower()
            End Using
        End Function

        Public Shared Function CalculateFileHash(filename As String) As String
            Using sha256 As SHA256 = SHA256.Create()
                Using fileStream As FileStream = File.OpenRead(filename)
                    Dim hashBytes As Byte() = sha256.ComputeHash(fileStream)
                    Return BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant()
                End Using
            End Using
        End Function
    End Class

    Class Utilities
        Public Shared Function HWID() As String
            Dim hwidValue As String = String.Empty

            Try
                Dim processStartInfo As New ProcessStartInfo With {
                    .FileName = "wmic",
                    .RedirectStandardOutput = True,
                    .UseShellExecute = False,
                    .CreateNoWindow = True,
                    .Arguments = "diskdrive get serialnumber"
                }

                Using process As New Process With {
                    .StartInfo = processStartInfo
                }
                    process.Start()
                    Dim output As String = process.StandardOutput.ReadToEnd()
                    process.WaitForExit()

                    If Not String.IsNullOrEmpty(output) Then
                        Dim lines As String() = output.Split(New Char() {Chr(13), Chr(10)}, StringSplitOptions.RemoveEmptyEntries)
                        If lines.Length > 1 Then
                            hwidValue = lines(1).Trim().TrimEnd("."c)
                        End If
                    End If
                End Using
            Catch ex As Exception
                hwidValue = "Error hwid: " & ex.Message
            End Try

            Return hwidValue
        End Function

        Public Shared Function IP() As String
            Dim externalIpString As String = New WebClient().DownloadString("http://icanhazip.com").Replace("\r\n", "").Replace("\n", "").Trim()
            Return externalIpString
        End Function
    End Class

    Class API
        Public ReadOnly ApiUrl As String
        Public ReadOnly AppName As String
        Public ReadOnly AppSecret As String
        Public ReadOnly AppVersion As String
        Public Initialized As Boolean

        Public Class ErrorData
            Public Property Code As String
            Public Property Message As String
        End Class

        Public appData As New ApplicationData()

        Public Class ApplicationData
            Public Property Id As String
            Public Property Name As String
            Public Property Status As Integer
            Public Property HwidCheck As Integer
            Public Property DeveloperMode As Integer
            Public Property IntegrityCheck As Integer
            Public Property FreeMode As Integer
            Public Property TwoFactorAuth As Integer
            Public Property ProgramHash As String
            Public Property Version As String
            Public Property DownloadLink As String
        End Class

        Public uData As New UserData()

        Public Class UserData
            Public Property Id As String
            Public Property Username As String
            Public Property Email As String
            Public Property ExpiryDate As String
            Public Property LastLogin As String
            Public Property LastIP As String
            Public Property HWID As String
            Public Property Token As String
        End Class

        Public Sub New(apiUrl As String, appName As String, appSecret As String, appVersion As String)
            Me.ApiUrl = apiUrl
            Me.AppName = appName
            Me.AppSecret = appSecret
            Me.AppVersion = appVersion
            Me.Initialized = False
        End Sub

        Public Sub Initialize()
            If Initialized Then
                Console.WriteLine("Application is already initialized!")
                Thread.Sleep(3000)
                Environment.Exit(0)
            End If

            Try
                Using client As New HttpClient()
                    Dim url As String = ApiUrl & "/applications/initialize"

                    client.DefaultRequestHeaders.Accept.Add(New MediaTypeWithQualityHeaderValue("application/json"))
                    client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json")

                    Dim jsonData As String = $"{{""name"":""{AppName}"",""secret"":""{AppSecret}"",""version"":""{AppVersion}""}}"
                    Dim content As New StringContent(jsonData, Encoding.UTF8, "application/json")
                    Dim response As HttpResponseMessage = client.PostAsync(url, content).Result

                    If response.IsSuccessStatusCode Then
                        Dim responseHash As String = response.Headers.GetValues("X-Response-Hash").FirstOrDefault()
                        Dim recalculatedHash As String = Security.CalculateResponseHash(response.Content.ReadAsStringAsync().Result)

                        If responseHash <> recalculatedHash Then
                            Console.WriteLine("Possible malicious activity detected!")
                            Thread.Sleep(3000)
                            Environment.Exit(0)
                        End If

                        Dim responseContent As String = response.Content.ReadAsStringAsync().Result
                        Dim serializer As New JavaScriptSerializer()
                        appData = DirectCast(serializer.Deserialize(responseContent, GetType(ApplicationData)), ApplicationData)
                        Initialized = True

                        If appData.Status = 0 Then
                            Console.WriteLine("Looks like this application is offline, please try again later!")
                            Thread.Sleep(3000)
                            Environment.Exit(0)
                        End If

                        If appData.FreeMode = 1 Then
                            Console.WriteLine("Application is in Free Mode!")
                        End If

                        If appData.DeveloperMode = 1 Then
                            Console.WriteLine("Application is in Developer Mode, bypassing integrity and update check!")
                            File.Create(Environment.CurrentDirectory & "/integrity.txt").Close()
                            Dim hash As String = Security.CalculateFileHash(Process.GetCurrentProcess().MainModule.FileName)
                            File.WriteAllText(Environment.CurrentDirectory & "/integrity.txt", hash)
                            Console.WriteLine("Your application's hash has been saved to integrity.txt, please refer to this when your application is ready for release!")
                        Else
                            If appData.Version <> AppVersion Then
                                Console.WriteLine($"Update {appData.Version} available, redirecting to update!")
                                Thread.Sleep(3000)
                                Process.Start(appData.DownloadLink)
                                Environment.Exit(0)
                            End If

                            If appData.IntegrityCheck = 1 Then
                                If appData.ProgramHash <> Security.CalculateFileHash(Process.GetCurrentProcess().MainModule.FileName) Then
                                    Console.WriteLine("File has been tampered with, couldn't verify integrity!")
                                    Thread.Sleep(3000)
                                    Environment.Exit(0)
                                End If
                            End If
                        End If
                    Else
                        Dim errorContent As String = response.Content.ReadAsStringAsync().Result
                        Dim serializer As New JavaScriptSerializer()
                        Dim errorData As ErrorData = DirectCast(serializer.Deserialize(errorContent, GetType(ErrorData)), ErrorData)
                        Console.WriteLine($"{errorData.Code}: {errorData.Message}")
                        Thread.Sleep(3000)
                        Environment.Exit(0)
                    End If
                End Using
            Catch ex As Exception
                Console.WriteLine($"An error occurred: {ex.Message}")
                Thread.Sleep(3000)
                Environment.Exit(0)
            End Try
        End Sub

        Public Function Register(username As String, password As String, email As String, license As String) As Boolean
            If Not Initialized Then
                Console.WriteLine("Please initialize your application first!")
                Thread.Sleep(3000)
                Return False
            End If

            Try
                Dim client As New HttpClient()
                Dim url As String = ApiUrl & "/users/register"

                client.DefaultRequestHeaders.Accept.Add(New MediaTypeWithQualityHeaderValue("application/json"))
                client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json")

                Dim jsonData As String = $"{{""username"":""{username}"",""password"":""{password}"",""email"":""{email}"",""license"":""{license}"",""hwid"":""{Utilities.HWID()}"",""lastIP"":""{Utilities.IP()}"",""applicationId"":""{appData.Id}""}}"
                Dim content As New StringContent(jsonData, Encoding.UTF8, "application/json")
                Dim response As HttpResponseMessage = client.PostAsync(url, content).Result

                If response.IsSuccessStatusCode Then
                    Dim responseHash As String = response.Headers.GetValues("X-Response-Hash").FirstOrDefault()
                    Dim recalculatedHash As String = Security.CalculateResponseHash(response.Content.ReadAsStringAsync().Result)

                    If responseHash <> recalculatedHash Then
                        Console.WriteLine("Possible malicious activity detected!")
                        Thread.Sleep(3000)
                        Environment.Exit(0)
                    End If

                    Dim responseContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    uData = CType(serializer.Deserialize(responseContent, GetType(UserData)), UserData)
                    Return True
                Else
                    Dim errorContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    Dim errorData As ErrorData = CType(serializer.Deserialize(errorContent, GetType(ErrorData)), ErrorData)
                    Console.WriteLine($"{errorData.Code}: {errorData.Message}")
                    Thread.Sleep(3000)
                    Return False
                End If
            Catch ex As Exception
                Console.WriteLine($"An error occurred: {ex.Message}")
                Thread.Sleep(3000)
                Return False
            End Try
        End Function

        Public Function Login(username As String, password As String, twoFactorCode As String) As Boolean
            If Not Initialized Then
                Console.WriteLine("Please initialize your application first!")
                Thread.Sleep(3000)
                Return False
            End If

            Try
                Dim client As New HttpClient()
                Dim url As String = ApiUrl & "/users/login"

                client.DefaultRequestHeaders.Accept.Add(New MediaTypeWithQualityHeaderValue("application/json"))
                client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json")

                Dim jsonData As String = $"{{""username"":""{username}"",""password"":""{password}"",""twoFactorCode"":""{twoFactorCode}"",""hwid"":""{Utilities.HWID()}"",""lastIP"":""{Utilities.IP()}"",""applicationId"":""{appData.Id}""}}"
                Dim content As New StringContent(jsonData, Encoding.UTF8, "application/json")
                Dim response As HttpResponseMessage = client.PostAsync(url, content).Result

                If response.IsSuccessStatusCode Then
                    Dim responseHash As String = response.Headers.GetValues("X-Response-Hash").FirstOrDefault()
                    Dim recalculatedHash As String = Security.CalculateResponseHash(response.Content.ReadAsStringAsync().Result)

                    If responseHash <> recalculatedHash Then
                        Console.WriteLine("Possible malicious activity detected!")
                        Thread.Sleep(3000)
                        Environment.Exit(0)
                    End If

                    Dim responseContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    uData = CType(serializer.Deserialize(responseContent, GetType(UserData)), UserData)
                    Return True
                Else
                    Dim errorContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    Dim errorData As ErrorData = CType(serializer.Deserialize(errorContent, GetType(ErrorData)), ErrorData)
                    Console.WriteLine($"{errorData.Code}: {errorData.Message}")
                    Thread.Sleep(3000)
                    Return False
                End If
            Catch ex As Exception
                Console.WriteLine($"An error occurred: {ex.Message}")
                Thread.Sleep(3000)
                Return False
            End Try
        End Function

        Public Function LoginLicenseOnly(license As String) As Boolean
            If Not Initialized Then
                Console.WriteLine("Please initialize your application first!")
                Thread.Sleep(3000)
                Return False
            End If

            Try
                Dim client As New HttpClient()
                Dim url As String = ApiUrl & "/licenses/login"

                client.DefaultRequestHeaders.Accept.Add(New MediaTypeWithQualityHeaderValue("application/json"))
                client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json")

                Dim jsonData As String = $"{{""license"":""{license}"",""hwid"":""{Utilities.HWID()}"",""lastIP"":""{Utilities.IP()}"",""applicationId"":""{appData.Id}""}}"
                Dim content As New StringContent(jsonData, Encoding.UTF8, "application/json")
                Dim response As HttpResponseMessage = client.PostAsync(url, content).Result

                If response.IsSuccessStatusCode Then
                    Dim responseHash As String = response.Headers.GetValues("X-Response-Hash").FirstOrDefault()
                    Dim recalculatedHash As String = Security.CalculateResponseHash(response.Content.ReadAsStringAsync().Result)

                    If responseHash <> recalculatedHash Then
                        Console.WriteLine("Possible malicious activity detected!")
                        Thread.Sleep(3000)
                        Environment.Exit(0)
                    End If

                    Dim responseContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    uData = CType(serializer.Deserialize(responseContent, GetType(UserData)), UserData)
                    Return True
                Else
                    Dim errorContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    Dim errorData As ErrorData = CType(serializer.Deserialize(errorContent, GetType(ErrorData)), ErrorData)
                    Console.WriteLine($"{errorData.Code}: {errorData.Message}")
                    Thread.Sleep(3000)
                    Return False
                End If
            Catch ex As Exception
                Console.WriteLine($"An error occurred: {ex.Message}")
                Thread.Sleep(3000)
                Return False
            End Try
        End Function

        Public Function Extend(username As String, password As String, license As String) As Boolean
            If Not Initialized Then
                Console.WriteLine("Please initialize your application first!")
                Thread.Sleep(3000)
                Return False
            End If

            Try
                Dim client As New HttpClient()
                Dim url As String = ApiUrl & "/users/upgrade"

                client.DefaultRequestHeaders.Accept.Add(New MediaTypeWithQualityHeaderValue("application/json"))
                client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json")

                Dim jsonData As String = $"{{""username"":""{username}"",""password"":""{password}"",""license"":""{license}"",""hwid"":""{Utilities.HWID()}"",""applicationId"":""{appData.Id}""}}"
                Dim content As New StringContent(jsonData, Encoding.UTF8, "application/json")
                Dim response As HttpResponseMessage = client.PutAsync(url, content).Result

                If response.IsSuccessStatusCode Then
                    Dim responseHash As String = response.Headers.GetValues("X-Response-Hash").FirstOrDefault()
                    Dim recalculatedHash As String = Security.CalculateResponseHash(response.Content.ReadAsStringAsync().Result)

                    If responseHash <> recalculatedHash Then
                        Console.WriteLine("Possible malicious activity detected!")
                        Thread.Sleep(3000)
                        Environment.Exit(0)
                    End If

                    Dim responseContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    uData = CType(serializer.Deserialize(responseContent, GetType(UserData)), UserData)
                    Return True
                Else
                    Dim errorContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    Dim errorData As ErrorData = CType(serializer.Deserialize(errorContent, GetType(ErrorData)), ErrorData)
                    Console.WriteLine($"{errorData.Code}: {errorData.Message}")
                    Thread.Sleep(3000)
                    Return False
                End If
            Catch ex As Exception
                Console.WriteLine($"An error occurred: {ex.Message}")
                Thread.Sleep(3000)
                Return False
            End Try
        End Function

        Public Sub Log(action As String)
            If Not Initialized Then
                Console.WriteLine("Please initialize your application first!")
                Return
            End If

            Try
                Dim client As New HttpClient()
                Dim url As String = ApiUrl & "/appLogs/"

                client.DefaultRequestHeaders.Accept.Add(New MediaTypeWithQualityHeaderValue("application/json"))
                client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json")
                client.DefaultRequestHeaders.Authorization = New AuthenticationHeaderValue("Bearer", uData.Token)

                Dim jsonData As String = $"{{""action"":""{action}"",""ip"":""{Utilities.IP()}"",""applicationId"":""{appData.Id}"",""userId"":""{uData.Id}""}}"
                Dim content As New StringContent(jsonData, Encoding.UTF8, "application/json")
                Dim response As HttpResponseMessage = client.PostAsync(url, content).Result

                If Not response.IsSuccessStatusCode Then
                    Dim errorContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    Dim errorData As ErrorData = CType(serializer.Deserialize(errorContent, GetType(ErrorData)), ErrorData)
                    Console.WriteLine($"{errorData.Code}: {errorData.Message}")
                End If
            Catch ex As Exception
                Console.WriteLine($"An error occurred: {ex.Message}")
            End Try
        End Sub

        Public Sub DownloadFile(fileId As String)
            If Not Initialized Then
                Console.WriteLine("Please initialize your application first!")
                Return
            End If

            Try
                Dim client As New HttpClient()
                Dim url As String = ApiUrl & $"/files/download/{fileId}"
                client.DefaultRequestHeaders.Authorization = New AuthenticationHeaderValue("Bearer", uData.Token)
                Dim response As HttpResponseMessage = client.GetAsync(url).Result
                Dim outputPath As String = String.Empty

                Dim contentDispositionValues As IEnumerable(Of String)

                If response.IsSuccessStatusCode Then
                    ' Extract the file name and extension from the response headers
                    If response.Content.Headers.TryGetValues("Content-Disposition", contentDispositionValues) Then
                        Dim contentDisposition As String = contentDispositionValues.FirstOrDefault()
                        If Not String.IsNullOrEmpty(contentDisposition) Then
                            Dim parts As String() = contentDisposition.Split("="c)
                            If parts.Length = 2 Then
                                Dim fileName As String = parts(1).Trim(""""c)
                                outputPath = Path.Combine(Directory.GetCurrentDirectory(), fileName)
                            End If
                        End If
                    End If
                    ' Save the file if outputPath is not empty
                    If Not String.IsNullOrEmpty(outputPath) Then
                        Dim contentStream As Stream = response.Content.ReadAsStreamAsync().Result
                        Dim fileStream As FileStream = File.Create(outputPath)
                        contentStream.CopyToAsync(fileStream)
                    Else
                        Console.WriteLine("Unable to determine the file name.")
                    End If
                Else
                    Dim errorContent As String = response.Content.ReadAsStringAsync().Result
                    Dim serializer As New JavaScriptSerializer()
                    Dim errorData As ErrorData = CType(serializer.Deserialize(errorContent, GetType(ErrorData)), ErrorData)
                    Console.WriteLine($"{errorData.Code}: {errorData.Message}")
                End If
            Catch ex As Exception
                Console.WriteLine($"An error occurred: {ex.Message}")
            End Try
        End Sub
    End Class
End Namespace
