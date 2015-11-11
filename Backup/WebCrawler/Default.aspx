<%@ Page Title="Home Page" Language="C#" MasterPageFile="~/Site.master" AutoEventWireup="true"
    CodeBehind="Default.aspx.cs" Inherits="WebCrawler._Default" MaintainScrollPositionOnPostback="true" %>

<asp:Content ID="HeaderContent" runat="server" ContentPlaceHolderID="HeadContent">
    <style type="text/css">
        .style2
        {
            font-size: medium;
            font-family: Arial;
        }
        .style5
        {
            font-size: medium;
        }
    </style>
</asp:Content>
<asp:Content ID="BodyContent" runat="server" ContentPlaceHolderID="MainContent">
    <asp:ScriptManager ID="ScriptManager1" runat="server">
    </asp:ScriptManager>
    <div style="height: 100%; overflow: hidden;">
        <asp:UpdatePanel ID="UpdatePanel1" runat="server">
            <ContentTemplate>
                <asp:Timer ID="Timer1" runat="server" OnTick="Timer1_Tick" Interval="10" Enabled="false">
                </asp:Timer>
                <asp:Label ID="Label1" runat="server" Text="Enter URL :" Style="font-weight: 700;
                    font-family: Arial"></asp:Label>
                <asp:TextBox ID="txtURL" runat="server" Height="22px" Style="margin-left: 12px" Width="333px"></asp:TextBox>
                <div style="height: 50px">
                </div>
                <a href="javascript:checkedAll(form1)"><font size="3">Check/Uncheck All</font></a><br>
                <br>
                <strong><span class="style2">Please select which vulnerabilities to test for:</span></strong><br
                    class="style5">
                <div>
                    <asp:CheckBoxList ID="CheckBoxList1" runat="server" Font-Bold="True" Font-Size="Medium"
                        ForeColor="#333333">
                        <asp:ListItem>Standard SQL Injection</asp:ListItem>
                        <asp:ListItem>Broken Authentication using SQL Injection</asp:ListItem>
                        <asp:ListItem>Reflected Cross-Site Scripting</asp:ListItem>
                        <asp:ListItem>Stored Cross-Site Scripting</asp:ListItem>
                    </asp:CheckBoxList>
                </div>
                <div>
                    <asp:Button ID="btnScan" runat="server" Text="Start Scan" Style="margin-left: 25px;
                        font-family: Arial;" Width="108px" OnClick="Button1_Click" />
                    <asp:Button ID="btnStop" runat="server" Text="Stop Scan" Style="margin-left: 25px;
                        font-family: Arial;" Width="108px" OnClick="btnStop_Click" />
                </div>
                <div>
                    <asp:Label ID="lbWarning" runat="server" Font-Size="Medium" ForeColor="#CC0000"></asp:Label>
                </div>
                <br />
                <div>
                    <asp:Label ID="Label4" runat="server" Text="CRAWLING STATUS" Font-Bold="True" Font-Size="Large"
                        ForeColor="Black"></asp:Label>
                </div>
                <div>
                    <asp:Label ID="Label3" runat="server" Text="No. of Links Crawled: " Font-Size="Medium"></asp:Label>
                    <asp:Label ID="lblNumCrawled" runat="server" Font-Size="Medium"></asp:Label>
                </div>
                <div>
                    <asp:Label ID="lbProgress" runat="server" ForeColor="Black" Style="font-weight: 700;
                        font-family: Arial"></asp:Label>
                </div>
                <div style="height: 50px">
                </div>
                <div>
                    <div style="border: 1px solid black; width: 49%; float: left;">
                        <asp:Label ID="lblDetection" runat="server" Text="SQL INJECTION" Font-Bold="True"
                            Font-Size="Large" ForeColor="Black"></asp:Label>
                        <br />
                        <asp:Label ID="label" runat="server" Text="No.of Vulnerabilities: " Font-Size="Medium"
                            Style="color: #003366"></asp:Label>
                        <asp:Label ID="lblNumVul" runat="server" Font-Size="Medium" Style="color: #FF0000"></asp:Label>
                        <br />
                        <div style="height:50px;"><asp:Label ID="lbSQL" runat="server" Style="color: #003366"></asp:Label></div>
                        <br />
                        <div id="showExtractContent" runat="server">
                        </div>
                    </div>
                    <div style="border: 1px solid black; width: 48%; float: right;">
                        <asp:Label ID="Label5" runat="server" Text="CROSS SITE SCRIPTING" Font-Bold="True"
                            Font-Size="Large" ForeColor="Black"></asp:Label>
                        <br />
                        <asp:Label ID="label7" runat="server" Text="No.of Vulnerabilities: " Font-Size="Medium"
                            Style="color: #003366"></asp:Label>
                        <asp:Label ID="lblNumVulXSS" runat="server" Font-Size="Medium" Style="color: #FF0000"></asp:Label>
                        <br />
                        <div style="height:50px;"><asp:Label ID="lbXSS" runat="server" Style="color: #003366"></asp:Label></div>
                        <div id="showExtractContentXSS" runat="server">
                        </div>
                    </div>
                    
                        <div style="clear: both">
                        </div>
                </div>
                <br />
                <div style="height: 50px">
                </div>
            </ContentTemplate>
        </asp:UpdatePanel>
        <br />
        <br />
    </div>
</asp:Content>
