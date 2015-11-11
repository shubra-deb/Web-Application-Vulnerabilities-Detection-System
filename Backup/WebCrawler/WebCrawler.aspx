<%@ Page Language="C#" Async="true" AutoEventWireup="true" CodeBehind="WebCrawler.aspx.cs"
    Inherits="WebCrawler.WebCrawler" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title></title>
   
</head>
<body>
    <form id="form1" runat="server">
    <asp:ScriptManager ID="ScriptManager1" runat="server">
    </asp:ScriptManager>
    <div>
        <asp:UpdatePanel ID="UpdatePanel1" runat="server">
            <ContentTemplate>
                <asp:Label ID="Label1" runat="server" Text="Enter URL :" Style="font-weight: 700;font-family: Arial"></asp:Label>

                <asp:TextBox ID="url_TextBox" runat="server" Height="22px" Style="margin-left: 12px" Width="333px"></asp:TextBox>

                <asp:Button ID="btnstart_crawling" runat="server" Text="Start Crawling" Style="margin-left: 25px" Width="108px" OnClick="Button1_Click" />
                <asp:Timer ID="Timer1" runat="server" Interval="100" Enabled="false" ontick="Timer1_Tick"> </asp:Timer>
                <div>
                    <asp:Label ID="lbProgress" runat="server" ForeColor="Black" Style="font-weight: 700;font-family: Arial"></asp:Label>
                </div>

                <div>
                <asp:Label ID="Label2" runat="server" Text="Vulnerabilities found: " 
                        Font-Bold="True" Font-Size="20px" ForeColor="#FF3300"></asp:Label>
                </div>
                <div>
                    <asp:GridView ID="GridViewLinks" runat="server">
                    </asp:GridView>
                </div>
            </ContentTemplate>
        </asp:UpdatePanel>
        <br />
        <br />
    </div>
    </form>
</body>
</html>
