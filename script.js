
// Wordlist Arsenal - Advanced Cybersecurity Tool
// Developed by 0x0806

class WordlistArsenal {
    constructor() {
        this.currentTab = 'dashboard';
        this.currentGenerator = 'enumeration';
        this.generationHistory = [];
        this.stats = {
            totalGenerated: 0,
            activeSessions: 1,
            totalDownloads: 0,
            mostUsed: 'None',
            generatorUsage: {}
        };
        this.generatedWordlists = [];
        this.currentWordlist = null;
        this.progressInterval = null;
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadStats();
        this.updateStatsDisplay();
        this.setupGenerators();
    }

    setupEventListeners() {
        // Tab navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.target.getAttribute('data-tab') || e.target.closest('.nav-tab').getAttribute('data-tab');
                this.switchTab(tabName);
            });
        });

        // Generator selection
        document.querySelectorAll('.generator-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const generatorName = e.target.getAttribute('data-generator') || e.target.closest('.generator-btn').getAttribute('data-generator');
                this.switchGenerator(generatorName);
            });
        });

        // Quick action buttons
        document.querySelectorAll('.action-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const generatorName = e.target.getAttribute('data-generator') || e.target.closest('.action-btn').getAttribute('data-generator');
                this.switchTab('generators');
                this.switchGenerator(generatorName);
            });
        });

        // FAB menu
        const fab = document.getElementById('fab');
        const fabMenu = document.getElementById('fabMenu');
        if (fab && fabMenu) {
            fab.addEventListener('click', () => {
                fab.classList.toggle('active');
                fabMenu.classList.toggle('active');
            });
        }

        // FAB menu items
        document.querySelectorAll('.fab-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const action = e.target.getAttribute('data-action') || e.target.closest('.fab-item').getAttribute('data-action');
                this.handleFabAction(action);
            });
        });

        // File upload
        this.setupFileUpload();

        // Output panel
        this.setupOutputPanel();

        // History actions
        this.setupHistoryActions();

        // Tools
        this.setupTools();

        // Modal close
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal-overlay')) {
                this.closeModal();
            }
        });
    }

    setupGenerators() {
        // Initialize with default generator
        this.loadGeneratorPanel(this.currentGenerator);
    }

    switchTab(tabName) {
        if (!tabName) return;
        
        // Update tab buttons
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        const activeTab = document.querySelector(`[data-tab="${tabName}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
        }

        // Update tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        const activeContent = document.getElementById(tabName);
        if (activeContent) {
            activeContent.classList.add('active');
        }

        this.currentTab = tabName;
    }

    switchGenerator(generatorName) {
        if (!generatorName) return;
        
        // Update generator buttons
        document.querySelectorAll('.generator-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        const activeBtn = document.querySelector(`[data-generator="${generatorName}"]`);
        if (activeBtn) {
            activeBtn.classList.add('active');
        }

        // Load generator panel
        this.loadGeneratorPanel(generatorName);
        this.currentGenerator = generatorName;
    }

    loadGeneratorPanel(generatorName) {
        const panel = document.getElementById('generatorPanel');
        if (!panel) return;

        const generators = {
            enumeration: this.createEnumerationPanel(),
            passwords: this.createPasswordPanel(),
            credentials: this.createCredentialsPanel(),
            usernames: this.createUsernamesPanel(),
            patterns: this.createPatternsPanel(),
            hybrid: this.createHybridPanel(),
            endpoints: this.createEndpointsPanel(),
            webtech: this.createWebtechPanel(),
            security: this.createSecurityPanel()
        };

        panel.innerHTML = generators[generatorName] || this.createDefaultPanel();
        this.setupGeneratorEvents(generatorName);
    }

    createEnumerationPanel() {
        return `
            <div class="panel-header">
                <h3>Web Discovery Wordlists</h3>
                <p>Generate wordlists for web directory and file enumeration</p>
            </div>
            
            <div class="config-section">
                <h4>Target Configuration</h4>
                <div class="form-group">
                    <label>Target Technology</label>
                    <select class="form-control" id="enumTech">
                        <option value="generic">Generic</option>
                        <option value="php">PHP</option>
                        <option value="asp">ASP.NET</option>
                        <option value="java">Java</option>
                        <option value="python">Python</option>
                        <option value="nodejs">Node.js</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Content Types</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="enumDirs" checked>
                            <label for="enumDirs">Directories</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="enumFiles" checked>
                            <label for="enumFiles">Files</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="enumBackups" checked>
                            <label for="enumBackups">Backup Files</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="enumConfigs" checked>
                            <label for="enumConfigs">Config Files</label>
                        </div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Extensions (comma-separated)</label>
                    <input type="text" class="form-control" id="enumExtensions" placeholder="php,html,js,css,txt">
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generateEnumeration()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="enumPreview">
                    admin
                    backup
                    config
                    login
                    test
                    ...
                </div>
            </div>
        `;
    }

    createPasswordPanel() {
        return `
            <div class="panel-header">
                <h3>Brute Force Password Lists</h3>
                <p>Generate custom password wordlists for brute force attacks</p>
            </div>
            
            <div class="config-section">
                <h4>Password Configuration</h4>
                <div class="form-group">
                    <label>Base Words (one per line)</label>
                    <textarea class="form-control" id="passBase" rows="4" placeholder="password
admin
user
company"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Password Rules</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="passNumbers" checked>
                            <label for="passNumbers">Add Numbers (0-999)</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="passYears" checked>
                            <label for="passYears">Add Years (1990-2024)</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="passSpecial">
                            <label for="passSpecial">Add Special Chars (!@#$)</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="passCase" checked>
                            <label for="passCase">Capitalize First Letter</label>
                        </div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Length Range</label>
                    <div style="display: flex; gap: 1rem;">
                        <input type="number" class="form-control" id="passMinLen" placeholder="Min" value="6">
                        <input type="number" class="form-control" id="passMaxLen" placeholder="Max" value="12">
                    </div>
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generatePasswords()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="passPreview">
                    Password123
                    admin2024
                    user!
                    Company1
                    ...
                </div>
            </div>
        `;
    }

    createCredentialsPanel() {
        return `
            <div class="panel-header">
                <h3>Default Credentials Database</h3>
                <p>Common default username:password combinations</p>
            </div>
            
            <div class="config-section">
                <h4>Credential Types</h4>
                <div class="checkbox-group">
                    <div class="checkbox-item">
                        <input type="checkbox" id="credGeneric" checked>
                        <label for="credGeneric">Generic Systems</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="credRouters" checked>
                        <label for="credRouters">Routers & Switches</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="credDatabases" checked>
                        <label for="credDatabases">Databases</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="credApps" checked>
                        <label for="credApps">Web Applications</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="credIoT" checked>
                        <label for="credIoT">IoT Devices</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" id="credCameras" checked>
                        <label for="credCameras">IP Cameras</label>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Output Format</label>
                    <select class="form-control" id="credFormat">
                        <option value="colon">username:password</option>
                        <option value="space">username password</option>
                        <option value="tab">username	password</option>
                        <option value="separate">Separate Lists</option>
                    </select>
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generateCredentials()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="credPreview">
                    admin:admin
                    admin:password
                    root:root
                    admin:123456
                    ...
                </div>
            </div>
        `;
    }

    createUsernamesPanel() {
        return `
            <div class="panel-header">
                <h3>Username Generator</h3>
                <p>Generate username lists based on personal information</p>
            </div>
            
            <div class="config-section">
                <h4>Personal Information</h4>
                <div class="form-group">
                    <label>First Names (one per line)</label>
                    <textarea class="form-control" id="userFirst" rows="3" placeholder="john
jane
mike"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Last Names (one per line)</label>
                    <textarea class="form-control" id="userLast" rows="3" placeholder="smith
doe
johnson"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Company/Organization</label>
                    <input type="text" class="form-control" id="userCompany" placeholder="acme">
                </div>
                
                <div class="form-group">
                    <label>Username Patterns</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="userFirstLast" checked>
                            <label for="userFirstLast">firstname.lastname</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="userFirstInitial" checked>
                            <label for="userFirstInitial">f.lastname</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="userLastFirst" checked>
                            <label for="userLastFirst">lastname.firstname</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="userFirstOnly" checked>
                            <label for="userFirstOnly">firstname</label>
                        </div>
                    </div>
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generateUsernames()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="userPreview">
                    john.smith
                    j.smith
                    smith.john
                    john
                    ...
                </div>
            </div>
        `;
    }

    createPatternsPanel() {
        return `
            <div class="panel-header">
                <h3>Custom Pattern Builder</h3>
                <p>Build wordlists using custom patterns and rules</p>
            </div>
            
            <div class="config-section">
                <h4>Pattern Configuration</h4>
                <div class="form-group">
                    <label>Pattern Template</label>
                    <input type="text" class="form-control" id="patternTemplate" placeholder="?w?d?d?d" 
                           title="?w=word, ?d=digit, ?l=lowercase, ?u=uppercase, ?s=special">
                    <small>?w=word, ?d=digit, ?l=lowercase, ?u=uppercase, ?s=special</small>
                </div>
                
                <div class="form-group">
                    <label>Base Words (one per line)</label>
                    <textarea class="form-control" id="patternWords" rows="4" placeholder="admin
test
user
pass"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Special Characters</label>
                    <input type="text" class="form-control" id="patternSpecial" value="!@#$%^&*">
                </div>
                
                <div class="form-group">
                    <label>Pattern Options</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="patternReverse">
                            <label for="patternReverse">Reverse Words</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="patternCase">
                            <label for="patternCase">Mixed Case</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="patternLeet">
                            <label for="patternLeet">Leet Speak (a=@, e=3, etc.)</label>
                        </div>
                    </div>
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generatePatterns()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="patternPreview">
                    admin123
                    test456
                    user789
                    pass!@#
                    ...
                </div>
            </div>
        `;
    }

    createHybridPanel() {
        return `
            <div class="panel-header">
                <h3>Hybrid Combiner</h3>
                <p>Combine multiple wordlists with intelligent mutations</p>
            </div>
            
            <div class="config-section">
                <h4>Source Lists</h4>
                <div class="form-group">
                    <label>Primary Wordlist (one per line)</label>
                    <textarea class="form-control" id="hybridPrimary" rows="4" placeholder="password
admin
user"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Secondary Wordlist (one per line)</label>
                    <textarea class="form-control" id="hybridSecondary" rows="4" placeholder="123
2024
!@#"></textarea>
                </div>
                
                <div class="form-group">
                    <label>Combination Rules</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="hybridAppend" checked>
                            <label for="hybridAppend">Append Secondary to Primary</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="hybridPrepend" checked>
                            <label for="hybridPrepend">Prepend Secondary to Primary</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="hybridInsert">
                            <label for="hybridInsert">Insert Secondary in Middle</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="hybridToggleCase">
                            <label for="hybridToggleCase">Toggle Case Variations</label>
                        </div>
                    </div>
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generateHybrid()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="hybridPreview">
                    password123
                    123password
                    admin2024
                    2024admin
                    ...
                </div>
            </div>
        `;
    }

    createEndpointsPanel() {
        return `
            <div class="panel-header">
                <h3>API Endpoint Wordlists</h3>
                <p>Generate API endpoint paths for REST and GraphQL discovery</p>
            </div>
            
            <div class="config-section">
                <h4>API Configuration</h4>
                <div class="form-group">
                    <label>API Type</label>
                    <select class="form-control" id="apiType">
                        <option value="rest">REST API</option>
                        <option value="graphql">GraphQL</option>
                        <option value="soap">SOAP</option>
                        <option value="generic">Generic API</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Endpoint Categories</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="apiAuth" checked>
                            <label for="apiAuth">Authentication</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="apiUsers" checked>
                            <label for="apiUsers">User Management</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="apiAdmin" checked>
                            <label for="apiAdmin">Admin Functions</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="apiFiles" checked>
                            <label for="apiFiles">File Operations</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="apiData" checked>
                            <label for="apiData">Data Access</label>
                        </div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>API Version</label>
                    <input type="text" class="form-control" id="apiVersion" placeholder="v1,v2,v3">
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generateEndpoints()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="apiPreview">
                    /api/v1/auth/login
                    /api/v1/users
                    /api/v1/admin/config
                    /api/v1/files/upload
                    ...
                </div>
            </div>
        `;
    }

    createWebtechPanel() {
        return `
            <div class="panel-header">
                <h3>Web Technology Paths</h3>
                <p>Technology-specific paths and files for web applications</p>
            </div>
            
            <div class="config-section">
                <h4>Technology Stack</h4>
                <div class="form-group">
                    <label>Web Technologies</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="techWordPress" checked>
                            <label for="techWordPress">WordPress</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="techDrupal" checked>
                            <label for="techDrupal">Drupal</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="techJoomla" checked>
                            <label for="techJoomla">Joomla</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="techLaravel" checked>
                            <label for="techLaravel">Laravel</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="techSymfony" checked>
                            <label for="techSymfony">Symfony</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="techSpring" checked>
                            <label for="techSpring">Spring Boot</label>
                        </div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Path Types</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="pathAdmin" checked>
                            <label for="pathAdmin">Admin Panels</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="pathConfig" checked>
                            <label for="pathConfig">Config Files</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="pathDebug" checked>
                            <label for="pathDebug">Debug Info</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="pathLogs" checked>
                            <label for="pathLogs">Log Files</label>
                        </div>
                    </div>
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generateWebtech()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="webtechPreview">
                    /wp-admin/
                    /wp-config.php
                    /admin/
                    /config/database.yml
                    ...
                </div>
            </div>
        `;
    }

    createSecurityPanel() {
        return `
            <div class="panel-header">
                <h3>Security Testing Wordlists</h3>
                <p>Specialized wordlists for security testing and penetration testing</p>
            </div>
            
            <div class="config-section">
                <h4>Security Test Types</h4>
                <div class="form-group">
                    <label>Test Categories</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="secXSS" checked>
                            <label for="secXSS">XSS Payloads</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="secSQLi" checked>
                            <label for="secSQLi">SQL Injection</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="secLFI" checked>
                            <label for="secLFI">LFI/RFI Paths</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="secCMDi" checked>
                            <label for="secCMDi">Command Injection</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="secFuzz" checked>
                            <label for="secFuzz">Fuzzing Strings</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="secBypass" checked>
                            <label for="secBypass">Filter Bypass</label>
                        </div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Payload Encoding</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="encURL" checked>
                            <label for="encURL">URL Encoding</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="encHTML" checked>
                            <label for="encHTML">HTML Encoding</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="encUnicode" checked>
                            <label for="encUnicode">Unicode Encoding</label>
                        </div>
                    </div>
                </div>
                
                <button class="btn-primary" onclick="wordlistArsenal.generateSecurity()">
                    <i class="fas fa-play"></i>
                    Generate Wordlist
                </button>
            </div>
            
            <div class="preview-section">
                <div class="preview-header">
                    <h4>Live Preview</h4>
                    <span class="preview-count">0 entries</span>
                </div>
                <div class="preview-content" id="securityPreview">
                    &lt;script&gt;alert('XSS')&lt;/script&gt;
                    ' OR '1'='1
                    ../../../etc/passwd
                    ; cat /etc/passwd
                    ...
                </div>
            </div>
        `;
    }

    createDefaultPanel() {
        return `
            <div class="panel-header">
                <h3>Select a Generator</h3>
                <p>Choose a wordlist generator from the sidebar to begin.</p>
            </div>
        `;
    }

    setupGeneratorEvents(generatorName) {
        // Add event listeners for real-time preview updates
        setTimeout(() => {
            const inputs = document.querySelectorAll('#generatorPanel input, #generatorPanel select, #generatorPanel textarea');
            inputs.forEach(input => {
                input.addEventListener('input', () => {
                    this.updatePreview(generatorName);
                });
                input.addEventListener('change', () => {
                    this.updatePreview(generatorName);
                });
            });
            
            // Initial preview update
            this.updatePreview(generatorName);
        }, 100);
    }

    updatePreview(generatorName) {
        // Update preview based on current settings
        setTimeout(() => {
            const previewElement = document.querySelector('#generatorPanel .preview-content');
            const countElement = document.querySelector('#generatorPanel .preview-count');
            
            if (previewElement && countElement) {
                const sampleData = this.generateSampleData(generatorName);
                previewElement.textContent = sampleData.slice(0, 10).join('\n') + (sampleData.length > 10 ? '\n...' : '');
                countElement.textContent = `${sampleData.length} entries`;
            }
        }, 100);
    }

    generateSampleData(generatorName) {
        // Generate sample data for preview based on current form values
        const samples = {
            enumeration: () => {
                const tech = document.getElementById('enumTech')?.value || 'generic';
                const base = ['admin', 'backup', 'config', 'login', 'test', 'uploads', 'images', 'scripts', 'styles', 'data'];
                return tech === 'php' ? [...base, 'index.php', 'config.php', 'admin.php'] : base;
            },
            passwords: () => {
                const base = document.getElementById('passBase')?.value?.split('\n').filter(w => w.trim()) || ['password', 'admin', 'user'];
                return base.slice(0, 3).map(w => w + '123');
            },
            credentials: () => ['admin:admin', 'admin:password', 'root:root', 'admin:123456', 'user:user', 'test:test'],
            usernames: () => {
                const first = document.getElementById('userFirst')?.value?.split('\n').filter(w => w.trim()) || ['john', 'jane'];
                const last = document.getElementById('userLast')?.value?.split('\n').filter(w => w.trim()) || ['smith', 'doe'];
                return first.slice(0, 2).map(f => last.slice(0, 2).map(l => f + '.' + l)).flat();
            },
            patterns: () => ['admin123', 'test456', 'user789', 'pass!@#', 'login$%^', 'secure&*('],
            hybrid: () => {
                const primary = document.getElementById('hybridPrimary')?.value?.split('\n').filter(w => w.trim()) || ['password'];
                const secondary = document.getElementById('hybridSecondary')?.value?.split('\n').filter(w => w.trim()) || ['123'];
                return primary.slice(0, 2).map(p => secondary.slice(0, 2).map(s => [p + s, s + p])).flat(2);
            },
            endpoints: () => ['/api/v1/auth/login', '/api/v1/users', '/api/v1/admin/config', '/api/v1/files/upload', '/api/v1/data/export'],
            webtech: () => ['/wp-admin/', '/wp-config.php', '/admin/', '/config/database.yml', '/debug/', '/logs/'],
            security: () => ['<script>alert("XSS")</script>', "' OR '1'='1", '../../../etc/passwd', '; cat /etc/passwd', '%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E']
        };
        
        const generator = samples[generatorName];
        return generator ? generator() : ['sample1', 'sample2', 'sample3'];
    }

    // Generator methods
    generateEnumeration() {
        this.showProgress('Generating enumeration wordlist...');
        
        setTimeout(() => {
            const tech = document.getElementById('enumTech')?.value || 'generic';
            const extensions = document.getElementById('enumExtensions')?.value || '';
            const includeDirs = document.getElementById('enumDirs')?.checked || false;
            const includeFiles = document.getElementById('enumFiles')?.checked || false;
            const includeBackups = document.getElementById('enumBackups')?.checked || false;
            const includeConfigs = document.getElementById('enumConfigs')?.checked || false;
            
            let wordlist = [];
            
            if (includeDirs) {
                wordlist.push(...this.getDirectoryWords(tech));
            }
            
            if (includeFiles) {
                wordlist.push(...this.getFileWords(tech));
            }
            
            if (includeBackups) {
                wordlist.push(...this.getBackupWords());
            }
            
            if (includeConfigs) {
                wordlist.push(...this.getConfigWords(tech));
            }
            
            if (extensions && includeFiles) {
                const exts = extensions.split(',').map(e => e.trim().replace(/^\./, ''));
                const baseWords = ['index', 'admin', 'test', 'login', 'config', 'main', 'app', 'home', 'default', 'search'];
                exts.forEach(ext => {
                    baseWords.forEach(base => {
                        wordlist.push(`${base}.${ext}`);
                    });
                });
            }
            
            this.displayWordlist([...new Set(wordlist)], 'Web Discovery Enumeration');
            this.updateStats('enumeration', wordlist.length);
            this.hideProgress();
        }, 1500);
    }

    generatePasswords() {
        this.showProgress('Generating password wordlist...');
        
        setTimeout(() => {
            const baseWords = document.getElementById('passBase')?.value.split('\n').filter(w => w.trim()) || ['password', 'admin', 'user', 'login'];
            const addNumbers = document.getElementById('passNumbers')?.checked || false;
            const addYears = document.getElementById('passYears')?.checked || false;
            const addSpecial = document.getElementById('passSpecial')?.checked || false;
            const capitalize = document.getElementById('passCase')?.checked || false;
            const minLen = parseInt(document.getElementById('passMinLen')?.value) || 0;
            const maxLen = parseInt(document.getElementById('passMaxLen')?.value) || 50;
            
            let wordlist = [];
            
            baseWords.forEach(word => {
                word = word.trim();
                if (!word) return;
                
                let variations = [word];
                if (capitalize) {
                    variations.push(word.charAt(0).toUpperCase() + word.slice(1));
                    variations.push(word.toUpperCase());
                }
                
                variations.forEach(variant => {
                    if (variant.length >= minLen && variant.length <= maxLen) {
                        wordlist.push(variant);
                    }
                    
                    if (addNumbers) {
                        for (let i = 0; i <= 999; i++) {
                            const combo = variant + i;
                            if (combo.length >= minLen && combo.length <= maxLen) {
                                wordlist.push(combo);
                            }
                        }
                    }
                    
                    if (addYears) {
                        for (let year = 1990; year <= 2024; year++) {
                            const combo = variant + year;
                            if (combo.length >= minLen && combo.length <= maxLen) {
                                wordlist.push(combo);
                            }
                        }
                    }
                    
                    if (addSpecial) {
                        const special = ['!', '@', '#', '$', '%', '&', '*'];
                        special.forEach(char => {
                            const combo = variant + char;
                            if (combo.length >= minLen && combo.length <= maxLen) {
                                wordlist.push(combo);
                            }
                        });
                    }
                });
            });
            
            this.displayWordlist([...new Set(wordlist)], 'Brute Force Passwords');
            this.updateStats('passwords', wordlist.length);
            this.hideProgress();
        }, 2000);
    }

    generateCredentials() {
        this.showProgress('Generating credentials database...');
        
        setTimeout(() => {
            const format = document.getElementById('credFormat')?.value || 'colon';
            const includeGeneric = document.getElementById('credGeneric')?.checked || false;
            const includeRouters = document.getElementById('credRouters')?.checked || false;
            const includeDatabases = document.getElementById('credDatabases')?.checked || false;
            const includeApps = document.getElementById('credApps')?.checked || false;
            const includeIoT = document.getElementById('credIoT')?.checked || false;
            const includeCameras = document.getElementById('credCameras')?.checked || false;
            
            let credentials = [];
            
            if (includeGeneric) {
                credentials.push(...this.getDefaultCredentials().generic);
            }
            if (includeRouters) {
                credentials.push(...this.getDefaultCredentials().routers);
            }
            if (includeDatabases) {
                credentials.push(...this.getDefaultCredentials().databases);
            }
            if (includeApps) {
                credentials.push(...this.getDefaultCredentials().apps);
            }
            if (includeIoT) {
                credentials.push(...this.getDefaultCredentials().iot);
            }
            if (includeCameras) {
                credentials.push(...this.getDefaultCredentials().cameras);
            }
            
            let wordlist = [];
            credentials.forEach(cred => {
                switch (format) {
                    case 'colon':
                        wordlist.push(`${cred.username}:${cred.password}`);
                        break;
                    case 'space':
                        wordlist.push(`${cred.username} ${cred.password}`);
                        break;
                    case 'tab':
                        wordlist.push(`${cred.username}\t${cred.password}`);
                        break;
                    case 'separate':
                        wordlist.push(cred.username, cred.password);
                        break;
                }
            });
            
            this.displayWordlist([...new Set(wordlist)], 'Default Credentials');
            this.updateStats('credentials', wordlist.length);
            this.hideProgress();
        }, 1000);
    }

    generateUsernames() {
        this.showProgress('Generating username list...');
        
        setTimeout(() => {
            const firstNames = document.getElementById('userFirst')?.value.split('\n').filter(w => w.trim()) || ['john', 'jane', 'mike', 'sarah'];
            const lastNames = document.getElementById('userLast')?.value.split('\n').filter(w => w.trim()) || ['smith', 'doe', 'johnson', 'williams'];
            const company = document.getElementById('userCompany')?.value.trim() || '';
            
            let wordlist = [];
            
            firstNames.forEach(first => {
                first = first.trim().toLowerCase();
                if (!first) return;
                
                lastNames.forEach(last => {
                    last = last.trim().toLowerCase();
                    if (!last) return;
                    
                    if (document.getElementById('userFirstLast')?.checked) {
                        wordlist.push(`${first}.${last}`);
                        wordlist.push(`${first}_${last}`);
                        wordlist.push(`${first}${last}`);
                    }
                    if (document.getElementById('userFirstInitial')?.checked) {
                        wordlist.push(`${first.charAt(0)}.${last}`);
                        wordlist.push(`${first.charAt(0)}${last}`);
                    }
                    if (document.getElementById('userLastFirst')?.checked) {
                        wordlist.push(`${last}.${first}`);
                        wordlist.push(`${last}_${first}`);
                        wordlist.push(`${last}${first}`);
                    }
                });
                
                if (document.getElementById('userFirstOnly')?.checked) {
                    wordlist.push(first);
                }
            });
            
            if (company) {
                const companyLower = company.toLowerCase();
                wordlist.push(companyLower);
                wordlist.push(`${companyLower}admin`);
                wordlist.push(`admin${companyLower}`);
                wordlist.push(`${companyLower}user`);
                wordlist.push(`user${companyLower}`);
            }
            
            this.displayWordlist([...new Set(wordlist)], 'Username List');
            this.updateStats('usernames', wordlist.length);
            this.hideProgress();
        }, 1000);
    }

    generatePatterns() {
        this.showProgress('Generating pattern-based wordlist...');
        
        setTimeout(() => {
            const template = document.getElementById('patternTemplate')?.value || '?w?d?d?d';
            const words = document.getElementById('patternWords')?.value.split('\n').filter(w => w.trim()) || ['admin', 'test', 'user', 'pass'];
            const specialChars = document.getElementById('patternSpecial')?.value || '!@#$%^&*';
            const doReverse = document.getElementById('patternReverse')?.checked || false;
            const doCase = document.getElementById('patternCase')?.checked || false;
            const doLeet = document.getElementById('patternLeet')?.checked || false;
            
            let wordlist = [];
            
            words.forEach(word => {
                word = word.trim();
                if (!word) return;
                
                let wordVariations = [word];
                if (doReverse) wordVariations.push(word.split('').reverse().join(''));
                if (doCase) {
                    wordVariations.push(word.toUpperCase());
                    wordVariations.push(word.toLowerCase());
                    wordVariations.push(word.charAt(0).toUpperCase() + word.slice(1));
                }
                if (doLeet) {
                    const leetWord = word.replace(/a/gi, '@').replace(/e/gi, '3').replace(/i/gi, '1').replace(/o/gi, '0').replace(/s/gi, '$');
                    wordVariations.push(leetWord);
                }
                
                wordVariations.forEach(wordVar => {
                    // Generate pattern instances
                    for (let i = 0; i < 10; i++) {
                        let result = template.replace(/\?w/g, wordVar);
                        result = result.replace(/\?d/g, () => Math.floor(Math.random() * 10));
                        result = result.replace(/\?l/g, () => String.fromCharCode(97 + Math.floor(Math.random() * 26)));
                        result = result.replace(/\?u/g, () => String.fromCharCode(65 + Math.floor(Math.random() * 26)));
                        result = result.replace(/\?s/g, () => specialChars[Math.floor(Math.random() * specialChars.length)]);
                        
                        wordlist.push(result);
                    }
                });
            });
            
            this.displayWordlist([...new Set(wordlist)], 'Custom Patterns');
            this.updateStats('patterns', wordlist.length);
            this.hideProgress();
        }, 1500);
    }

    generateHybrid() {
        this.showProgress('Generating hybrid wordlist...');
        
        setTimeout(() => {
            const primary = document.getElementById('hybridPrimary')?.value.split('\n').filter(w => w.trim()) || ['password', 'admin', 'user'];
            const secondary = document.getElementById('hybridSecondary')?.value.split('\n').filter(w => w.trim()) || ['123', '2024', '!@#'];
            const doAppend = document.getElementById('hybridAppend')?.checked || false;
            const doPrepend = document.getElementById('hybridPrepend')?.checked || false;
            const doInsert = document.getElementById('hybridInsert')?.checked || false;
            const doToggleCase = document.getElementById('hybridToggleCase')?.checked || false;
            
            let wordlist = [];
            
            primary.forEach(p => {
                p = p.trim();
                if (!p) return;
                
                secondary.forEach(s => {
                    s = s.trim();
                    if (!s) return;
                    
                    let combinations = [];
                    
                    if (doAppend) {
                        combinations.push(p + s);
                    }
                    if (doPrepend) {
                        combinations.push(s + p);
                    }
                    if (doInsert) {
                        const mid = Math.floor(p.length / 2);
                        combinations.push(p.slice(0, mid) + s + p.slice(mid));
                    }
                    
                    combinations.forEach(combo => {
                        wordlist.push(combo);
                        if (doToggleCase) {
                            wordlist.push(combo.toUpperCase());
                            wordlist.push(combo.toLowerCase());
                            wordlist.push(combo.charAt(0).toUpperCase() + combo.slice(1));
                        }
                    });
                });
            });
            
            this.displayWordlist([...new Set(wordlist)], 'Hybrid Combinations');
            this.updateStats('hybrid', wordlist.length);
            this.hideProgress();
        }, 1500);
    }

    generateEndpoints() {
        this.showProgress('Generating API endpoints...');
        
        setTimeout(() => {
            const apiType = document.getElementById('apiType')?.value || 'rest';
            const versions = document.getElementById('apiVersion')?.value.split(',').map(v => v.trim()) || ['v1'];
            const includeAuth = document.getElementById('apiAuth')?.checked || false;
            const includeUsers = document.getElementById('apiUsers')?.checked || false;
            const includeAdmin = document.getElementById('apiAdmin')?.checked || false;
            const includeFiles = document.getElementById('apiFiles')?.checked || false;
            const includeData = document.getElementById('apiData')?.checked || false;
            
            let wordlist = [];
            
            versions.forEach(version => {
                if (includeAuth) {
                    wordlist.push(...this.getAuthEndpoints(apiType, version));
                }
                if (includeUsers) {
                    wordlist.push(...this.getUserEndpoints(apiType, version));
                }
                if (includeAdmin) {
                    wordlist.push(...this.getAdminEndpoints(apiType, version));
                }
                if (includeFiles) {
                    wordlist.push(...this.getFileEndpoints(apiType, version));
                }
                if (includeData) {
                    wordlist.push(...this.getDataEndpoints(apiType, version));
                }
            });
            
            if (apiType === 'graphql') {
                wordlist.push('/graphql', '/graphiql', '/graphql/playground', '/graphql/voyager');
            }
            
            this.displayWordlist([...new Set(wordlist)], 'API Endpoints');
            this.updateStats('endpoints', wordlist.length);
            this.hideProgress();
        }, 1000);
    }

    generateWebtech() {
        this.showProgress('Generating web technology paths...');
        
        setTimeout(() => {
            let wordlist = [];
            
            if (document.getElementById('techWordPress')?.checked) {
                wordlist.push(...this.getWordPressPaths());
            }
            if (document.getElementById('techDrupal')?.checked) {
                wordlist.push(...this.getDrupalPaths());
            }
            if (document.getElementById('techJoomla')?.checked) {
                wordlist.push(...this.getJoomlaPaths());
            }
            if (document.getElementById('techLaravel')?.checked) {
                wordlist.push(...this.getLaravelPaths());
            }
            if (document.getElementById('techSymfony')?.checked) {
                wordlist.push(...this.getSymfonyPaths());
            }
            if (document.getElementById('techSpring')?.checked) {
                wordlist.push(...this.getSpringPaths());
            }
            
            this.displayWordlist([...new Set(wordlist)], 'Web Technology Paths');
            this.updateStats('webtech', wordlist.length);
            this.hideProgress();
        }, 1500);
    }

    generateSecurity() {
        this.showProgress('Generating security test payloads...');
        
        setTimeout(() => {
            let wordlist = [];
            
            if (document.getElementById('secXSS')?.checked) {
                wordlist.push(...this.getXSSPayloads());
            }
            if (document.getElementById('secSQLi')?.checked) {
                wordlist.push(...this.getSQLiPayloads());
            }
            if (document.getElementById('secLFI')?.checked) {
                wordlist.push(...this.getLFIPayloads());
            }
            if (document.getElementById('secCMDi')?.checked) {
                wordlist.push(...this.getCMDiPayloads());
            }
            if (document.getElementById('secFuzz')?.checked) {
                wordlist.push(...this.getFuzzPayloads());
            }
            if (document.getElementById('secBypass')?.checked) {
                wordlist.push(...this.getBypassPayloads());
            }
            
            // Apply encoding if requested
            let encodedWordlist = [...wordlist];
            if (document.getElementById('encURL')?.checked) {
                encodedWordlist.push(...wordlist.map(payload => encodeURIComponent(payload)));
            }
            if (document.getElementById('encHTML')?.checked) {
                encodedWordlist.push(...wordlist.map(payload => 
                    payload.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;')
                ));
            }
            if (document.getElementById('encUnicode')?.checked) {
                encodedWordlist.push(...wordlist.map(payload => 
                    payload.split('').map(char => '\\u' + char.charCodeAt(0).toString(16).padStart(4, '0')).join('')
                ));
            }
            
            this.displayWordlist([...new Set(encodedWordlist)], 'Security Test Payloads');
            this.updateStats('security', encodedWordlist.length);
            this.hideProgress();
        }, 2000);
    }

    // Data source methods
    getDirectoryWords(tech) {
        const base = ['admin', 'backup', 'config', 'uploads', 'images', 'scripts', 'styles', 'data', 'files', 'docs', 'downloads', 'temp', 'cache', 'logs', 'debug', 'test', 'dev', 'api', 'assets', 'media', 'content', 'static', 'public', 'private', 'secure', 'hidden'];
        
        const techSpecific = {
            php: ['includes', 'lib', 'vendor', 'composer'],
            asp: ['bin', 'App_Data', 'App_Code', 'App_GlobalResources'],
            java: ['WEB-INF', 'META-INF', 'classes', 'lib'],
            python: ['static', 'templates', 'migrations', '__pycache__'],
            nodejs: ['node_modules', 'public', 'views', 'routes']
        };
        
        return [...base, ...(techSpecific[tech] || [])];
    }

    getFileWords(tech) {
        const base = ['index', 'admin', 'login', 'config', 'main', 'app', 'test', 'info', 'status', 'health', 'robots.txt', 'sitemap.xml', '.htaccess'];
        
        const techSpecific = {
            php: ['index.php', 'config.php', 'admin.php', 'login.php', 'info.php', 'phpinfo.php', 'wp-config.php'],
            asp: ['default.aspx', 'web.config', 'admin.aspx', 'login.aspx', 'global.asax'],
            java: ['index.jsp', 'admin.jsp', 'web.xml', 'struts.xml', 'applicationContext.xml'],
            python: ['app.py', 'main.py', 'config.py', 'settings.py', 'manage.py', 'wsgi.py', 'requirements.txt'],
            nodejs: ['package.json', 'server.js', 'app.js', 'index.js', 'gulpfile.js', 'webpack.config.js']
        };
        
        return [...base, ...(techSpecific[tech] || [])];
    }

    getBackupWords() {
        return ['backup', 'bak', 'old', 'orig', 'copy', 'save', 'tmp', 'temp', 'backup.zip', 'backup.tar.gz', 'backup.sql', 'dump.sql', 'backup.bak', 'site_backup.zip', 'db_backup.sql'];
    }

    getConfigWords(tech) {
        const base = ['config', 'configuration', 'settings', 'options', 'preferences', '.env', 'environment'];
        
        const techSpecific = {
            php: ['wp-config.php', 'config.inc.php', 'configuration.php', 'config.ini'],
            asp: ['web.config', 'app.config', 'machine.config', 'appsettings.json'],
            java: ['application.properties', 'config.properties', 'hibernate.cfg.xml', 'spring.xml'],
            python: ['settings.py', 'config.py', 'local_settings.py', 'production.py', 'development.py'],
            nodejs: ['config.json', '.env', 'package.json', '.npmrc', 'ecosystem.config.js']
        };
        
        return [...base, ...(techSpecific[tech] || [])];
    }

    getDefaultCredentials() {
        return {
            generic: [
                { username: 'admin', password: 'admin' },
                { username: 'admin', password: 'password' },
                { username: 'admin', password: '123456' },
                { username: 'root', password: 'root' },
                { username: 'user', password: 'user' },
                { username: 'test', password: 'test' },
                { username: 'guest', password: 'guest' },
                { username: 'administrator', password: 'administrator' },
                { username: 'admin', password: '' },
                { username: 'root', password: 'toor' }
            ],
            routers: [
                { username: 'admin', password: 'admin' },
                { username: 'admin', password: 'password' },
                { username: 'admin', password: '' },
                { username: 'root', password: 'root' },
                { username: 'cisco', password: 'cisco' },
                { username: 'netgear', password: 'password' },
                { username: 'linksys', password: 'admin' }
            ],
            databases: [
                { username: 'root', password: '' },
                { username: 'root', password: 'root' },
                { username: 'mysql', password: 'mysql' },
                { username: 'postgres', password: 'postgres' },
                { username: 'sa', password: 'sa' },
                { username: 'oracle', password: 'oracle' },
                { username: 'admin', password: 'admin' }
            ],
            apps: [
                { username: 'admin', password: 'admin' },
                { username: 'admin', password: 'password' },
                { username: 'administrator', password: 'password' },
                { username: 'demo', password: 'demo' },
                { username: 'test', password: 'test' },
                { username: 'guest', password: 'guest' }
            ],
            iot: [
                { username: 'admin', password: 'admin' },
                { username: 'admin', password: '' },
                { username: 'root', password: 'root' },
                { username: 'pi', password: 'raspberry' },
                { username: 'ubuntu', password: 'ubuntu' },
                { username: 'user', password: 'user' }
            ],
            cameras: [
                { username: 'admin', password: 'admin' },
                { username: 'admin', password: '' },
                { username: 'admin', password: '123456' },
                { username: 'root', password: 'root' },
                { username: 'viewer', password: 'viewer' },
                { username: 'camera', password: 'camera' }
            ]
        };
    }

    getAuthEndpoints(apiType, version) {
        const base = [
            `/api/${version}/auth/login`,
            `/api/${version}/auth/logout`,
            `/api/${version}/auth/register`,
            `/api/${version}/auth/refresh`,
            `/api/${version}/auth/reset`,
            `/api/${version}/auth/verify`,
            `/api/${version}/login`,
            `/api/${version}/logout`,
            `/api/${version}/register`,
            `/api/${version}/token`
        ];
        
        if (apiType === 'rest') {
            base.push(`/api/${version}/oauth/token`, `/api/${version}/oauth/authorize`);
        }
        
        return base;
    }

    getUserEndpoints(apiType, version) {
        return [
            `/api/${version}/users`,
            `/api/${version}/users/profile`,
            `/api/${version}/users/me`,
            `/api/${version}/users/settings`,
            `/api/${version}/user`,
            `/api/${version}/profile`,
            `/api/${version}/account`,
            `/api/${version}/me`
        ];
    }

    getAdminEndpoints(apiType, version) {
        return [
            `/api/${version}/admin`,
            `/api/${version}/admin/users`,
            `/api/${version}/admin/config`,
            `/api/${version}/admin/settings`,
            `/api/${version}/admin/logs`,
            `/api/${version}/admin/stats`,
            `/api/${version}/admin/dashboard`,
            `/api/${version}/management`,
            `/api/${version}/control`
        ];
    }

    getFileEndpoints(apiType, version) {
        return [
            `/api/${version}/files`,
            `/api/${version}/files/upload`,
            `/api/${version}/files/download`,
            `/api/${version}/upload`,
            `/api/${version}/download`,
            `/api/${version}/media`,
            `/api/${version}/attachments`,
            `/api/${version}/documents`
        ];
    }

    getDataEndpoints(apiType, version) {
        return [
            `/api/${version}/data`,
            `/api/${version}/data/export`,
            `/api/${version}/data/import`,
            `/api/${version}/export`,
            `/api/${version}/import`,
            `/api/${version}/backup`,
            `/api/${version}/restore`,
            `/api/${version}/sync`
        ];
    }

    getWordPressPaths() {
        return [
            '/wp-admin/',
            '/wp-content/',
            '/wp-includes/',
            '/wp-config.php',
            '/wp-login.php',
            '/wp-admin/admin-ajax.php',
            '/xmlrpc.php',
            '/readme.html',
            '/wp-content/uploads/',
            '/wp-content/themes/',
            '/wp-content/plugins/',
            '/wp-admin/install.php',
            '/wp-admin/upgrade.php',
            '/wp-trackback.php',
            '/wp-comments-post.php'
        ];
    }

    getDrupalPaths() {
        return [
            '/admin/',
            '/user/login',
            '/user/register',
            '/sites/default/',
            '/sites/all/',
            '/modules/',
            '/themes/',
            '/core/',
            '/CHANGELOG.txt',
            '/INSTALL.txt',
            '/LICENSE.txt',
            '/README.txt',
            '/cron.php',
            '/update.php',
            '/install.php'
        ];
    }

    getJoomlaPaths() {
        return [
            '/administrator/',
            '/components/',
            '/modules/',
            '/plugins/',
            '/templates/',
            '/libraries/',
            '/configuration.php',
            '/index.php',
            '/htaccess.txt',
            '/web.config.txt',
            '/LICENSE.txt',
            '/README.txt'
        ];
    }

    getLaravelPaths() {
        return [
            '/storage/',
            '/bootstrap/',
            '/vendor/',
            '/config/',
            '/database/',
            '/public/',
            '/resources/',
            '/routes/',
            '/app/',
            '/.env',
            '/artisan',
            '/composer.json',
            '/composer.lock',
            '/package.json'
        ];
    }

    getSymfonyPaths() {
        return [
            '/config/',
            '/public/',
            '/src/',
            '/templates/',
            '/var/',
            '/vendor/',
            '/bin/',
            '/.env',
            '/composer.json',
            '/composer.lock',
            '/symfony.lock'
        ];
    }

    getSpringPaths() {
        return [
            '/WEB-INF/',
            '/META-INF/',
            '/classes/',
            '/lib/',
            '/static/',
            '/templates/',
            '/application.properties',
            '/application.yml',
            '/pom.xml',
            '/build.gradle'
        ];
    }

    getXSSPayloads() {
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '"><script>alert("XSS")</script>',
            '\';alert("XSS");//',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<div onmouseover="alert(\'XSS\')">test</div>',
            '<script>console.log("XSS")</script>'
        ];
    }

    getSQLiPayloads() {
        return [
            "' OR '1'='1",
            '" OR "1"="1',
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL--",
            "admin'--",
            "' OR 1=1#",
            "' OR 'a'='a",
            '" OR 1=1--',
            "' UNION SELECT username, password FROM users--",
            "1' OR '1'='1' /*"
        ];
    }

    getLFIPayloads() {
        return [
            '../../../etc/passwd',
            '../../../windows/system32/drivers/etc/hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/etc/passwd',
            '/proc/self/environ',
            '/var/log/apache2/access.log',
            'C:\\windows\\system32\\drivers\\etc\\hosts'
        ];
    }

    getCMDiPayloads() {
        return [
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '& cat /etc/passwd',
            '&& cat /etc/passwd',
            '|| cat /etc/passwd',
            '`cat /etc/passwd`',
            '$(cat /etc/passwd)',
            '; ls -la',
            '| whoami',
            '& id'
        ];
    }

    getFuzzPayloads() {
        return [
            'A'.repeat(100),
            'A'.repeat(1000),
            'A'.repeat(10000),
            '0'.repeat(100),
            '%s%s%s%s%s%s%s%s%s%s',
            '%x%x%x%x%x%x%x%x%x%x',
            '../' * 100,
            '\\' * 100,
            '/' * 100,
            '%00' * 100
        ];
    }

    getBypassPayloads() {
        return [
            'admin\' --',
            'admin\' #',
            'admin\'/*',
            'admin\' or \'1\'=\'1\' --',
            'admin\' or \'1\'=\'1\' #',
            'admin\' or \'1\'=\'1\'/*',
            '\' or 1=1 --',
            '\' or 1=1 #',
            '\' or 1=1/*',
            'admin\') --',
            'admin\') #'
        ];
    }

    // UI Methods
    displayWordlist(wordlist, title) {
        const outputPanel = document.getElementById('outputPanel');
        const outputContent = document.getElementById('outputContent');
        const outputCount = document.getElementById('outputCount');
        const outputSize = document.getElementById('outputSize');
        const outputUnique = document.getElementById('outputUnique');
        const outputAvgLength = document.getElementById('outputAvgLength');
        
        if (!outputPanel || !outputContent) return;
        
        // Remove duplicates
        const uniqueWordlist = [...new Set(wordlist)];
        
        // Calculate stats
        const content = uniqueWordlist.join('\n');
        const sizeBytes = new Blob([content]).size;
        const avgLength = uniqueWordlist.length > 0 ? uniqueWordlist.reduce((sum, word) => sum + word.length, 0) / uniqueWordlist.length : 0;
        
        // Update display
        outputContent.value = content;
        if (outputCount) outputCount.textContent = uniqueWordlist.length.toLocaleString();
        if (outputSize) outputSize.textContent = this.formatBytes(sizeBytes);
        if (outputUnique) outputUnique.textContent = uniqueWordlist.length.toLocaleString();
        if (outputAvgLength) outputAvgLength.textContent = avgLength.toFixed(1);
        
        // Store for download
        this.currentWordlist = {
            content: content,
            title: title,
            count: uniqueWordlist.length
        };
        
        // Show panel
        outputPanel.classList.add('active');
        
        // Add to history
        this.addToHistory(title, uniqueWordlist.length, sizeBytes);
    }

    showProgress(message) {
        const indicator = document.getElementById('progressIndicator');
        const text = document.getElementById('progressText');
        const fill = document.getElementById('progressFill');
        
        if (!indicator || !text || !fill) return;
        
        text.textContent = message;
        indicator.classList.add('active');
        
        let progress = 0;
        const interval = setInterval(() => {
            progress += Math.random() * 30;
            if (progress > 90) progress = 90;
            fill.style.width = progress + '%';
        }, 100);
        
        this.progressInterval = interval;
    }

    hideProgress() {
        const indicator = document.getElementById('progressIndicator');
        const fill = document.getElementById('progressFill');
        
        if (!indicator || !fill) return;
        
        fill.style.width = '100%';
        setTimeout(() => {
            indicator.classList.remove('active');
            fill.style.width = '0%';
            if (this.progressInterval) {
                clearInterval(this.progressInterval);
                this.progressInterval = null;
            }
        }, 500);
    }

    setupOutputPanel() {
        const copyBtn = document.getElementById('copyOutput');
        const downloadBtn = document.getElementById('downloadOutput');
        const closeBtn = document.getElementById('closeOutput');
        
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                if (this.currentWordlist) {
                    navigator.clipboard.writeText(this.currentWordlist.content).then(() => {
                        this.showToast('Success', 'Wordlist copied to clipboard!', 'success');
                    }).catch(() => {
                        this.showToast('Error', 'Failed to copy to clipboard', 'error');
                    });
                }
            });
        }

        if (downloadBtn) {
            downloadBtn.addEventListener('click', () => {
                if (this.currentWordlist) {
                    this.downloadWordlist(this.currentWordlist.content, this.currentWordlist.title);
                }
            });
        }

        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                document.getElementById('outputPanel').classList.remove('active');
            });
        }
    }

    downloadWordlist(content, title) {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}_${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        this.stats.totalDownloads++;
        this.updateStatsDisplay();
        this.showToast('Success', 'Wordlist downloaded successfully!', 'success');
    }

    setupFileUpload() {
        const uploadArea = document.getElementById('uploadArea');
        const fileInput = document.getElementById('fileInput');
        
        if (!uploadArea || !fileInput) return;
        
        uploadArea.addEventListener('click', () => fileInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            this.handleFiles(e.dataTransfer.files);
        });
        
        fileInput.addEventListener('change', (e) => {
            this.handleFiles(e.target.files);
        });
    }

    handleFiles(files) {
        Array.from(files).forEach(file => {
            if (file.type === 'text/plain' || file.name.endsWith('.txt')) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    this.analyzeWordlist(e.target.result, file.name);
                };
                reader.readAsText(file);
            } else {
                this.showToast('Error', 'Please upload only text files (.txt)', 'error');
            }
        });
    }

    analyzeWordlist(content, filename) {
        const lines = content.split('\n').filter(line => line.trim());
        const unique = [...new Set(lines)];
        const avgLength = lines.length > 0 ? lines.reduce((sum, line) => sum + line.length, 0) / lines.length : 0;
        
        const analysis = {
            filename,
            totalLines: lines.length,
            uniqueLines: unique.length,
            duplicates: lines.length - unique.length,
            avgLength: avgLength.toFixed(2),
            minLength: lines.length > 0 ? Math.min(...lines.map(l => l.length)) : 0,
            maxLength: lines.length > 0 ? Math.max(...lines.map(l => l.length)) : 0,
            size: new Blob([content]).size
        };
        
        this.displayAnalysis(analysis);
    }

    displayAnalysis(analysis) {
        const resultsDiv = document.getElementById('analysisResults');
        if (!resultsDiv) return;
        
        resultsDiv.style.display = 'block';
        resultsDiv.innerHTML = `
            <div class="analysis-card">
                <h3><i class="fas fa-file-alt"></i> ${analysis.filename}</h3>
                <div class="analysis-stats">
                    <div class="stat">
                        <span class="stat-label">Total Lines:</span>
                        <span class="stat-value">${analysis.totalLines.toLocaleString()}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Unique Lines:</span>
                        <span class="stat-value">${analysis.uniqueLines.toLocaleString()}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Duplicates:</span>
                        <span class="stat-value">${analysis.duplicates.toLocaleString()}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Avg Length:</span>
                        <span class="stat-value">${analysis.avgLength}</span>
                    </div>
                    <div class="stat">
                        <span class="stat-label">Size:</span>
                        <span class="stat-value">${this.formatBytes(analysis.size)}</span>
                    </div>
                </div>
            </div>
        `;
    }

    addToHistory(title, count, size) {
        const historyItem = {
            id: Date.now(),
            title,
            count,
            size,
            generator: this.currentGenerator,
            timestamp: new Date().toISOString()
        };
        
        this.generationHistory.unshift(historyItem);
        this.updateHistoryDisplay();
        this.saveHistory();
    }

    updateHistoryDisplay() {
        const historyList = document.getElementById('historyList');
        if (!historyList) return;
        
        if (this.generationHistory.length === 0) {
            historyList.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-history"></i>
                    <h3>No Generation History</h3>
                    <p>Your wordlist generation history will appear here.</p>
                </div>
            `;
            return;
        }
        
        historyList.innerHTML = this.generationHistory.map(item => `
            <div class="history-item">
                <div class="history-info">
                    <h4>${item.title}</h4>
                    <div class="history-meta">
                        <span><i class="fas fa-list"></i> ${item.count.toLocaleString()} words</span>
                        <span><i class="fas fa-weight"></i> ${this.formatBytes(item.size)}</span>
                        <span><i class="fas fa-cog"></i> ${item.generator}</span>
                        <span><i class="fas fa-clock"></i> ${new Date(item.timestamp).toLocaleString()}</span>
                    </div>
                </div>
                <div class="history-actions-item">
                    <button class="btn-icon" onclick="wordlistArsenal.regenerateFromHistory(${item.id})" title="Regenerate">
                        <i class="fas fa-redo"></i>
                    </button>
                    <button class="btn-icon" onclick="wordlistArsenal.deleteHistoryItem(${item.id})" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        `).join('');
    }

    setupHistoryActions() {
        const clearBtn = document.getElementById('clearHistory');
        const exportBtn = document.getElementById('exportHistory');
        
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                this.generationHistory = [];
                this.updateHistoryDisplay();
                this.saveHistory();
                this.showToast('Success', 'History cleared successfully!', 'success');
            });
        }

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                const csv = this.generateHistoryCSV();
                this.downloadWordlist(csv, 'generation_history.csv');
            });
        }
    }

    generateHistoryCSV() {
        const headers = 'Title,Count,Size,Generator,Timestamp\n';
        const rows = this.generationHistory.map(item => 
            `"${item.title}",${item.count},${item.size},"${item.generator}","${item.timestamp}"`
        ).join('\n');
        return headers + rows;
    }

    setupTools() {
        const filterBtn = document.getElementById('filterTool');
        const mergeBtn = document.getElementById('mergeTool');
        const ruleBtn = document.getElementById('ruleTool');
        const statsBtn = document.getElementById('statsTool');
        
        if (filterBtn) {
            filterBtn.addEventListener('click', () => {
                this.openFilterTool();
            });
        }

        if (mergeBtn) {
            mergeBtn.addEventListener('click', () => {
                this.openMergeTool();
            });
        }

        if (ruleBtn) {
            ruleBtn.addEventListener('click', () => {
                this.openRuleTool();
            });
        }

        if (statsBtn) {
            statsBtn.addEventListener('click', () => {
                this.openStatsTool();
            });
        }
    }

    openFilterTool() {
        this.showModal('Filter & Clean Tool', `
            <div class="tool-content">
                <div class="form-group">
                    <label>Input Wordlist (one word per line)</label>
                    <textarea class="form-control" id="filterInput" rows="6" placeholder="Enter your wordlist here..."></textarea>
                </div>
                <div class="form-group">
                    <label>Filter Options</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="removeDuplicates" checked>
                            <label for="removeDuplicates">Remove Duplicates</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="removeEmpty" checked>
                            <label for="removeEmpty">Remove Empty Lines</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="sortAlpha">
                            <label for="sortAlpha">Sort Alphabetically</label>
                        </div>
                    </div>
                </div>
                <div class="form-group">
                    <label>Length Filter</label>
                    <div style="display: flex; gap: 1rem;">
                        <input type="number" class="form-control" id="minLength" placeholder="Min Length">
                        <input type="number" class="form-control" id="maxLength" placeholder="Max Length">
                    </div>
                </div>
                <div class="modal-actions">
                    <button class="btn-secondary" onclick="wordlistArsenal.closeModal()">Cancel</button>
                    <button class="btn-primary" onclick="wordlistArsenal.applyFilter()">Apply Filter</button>
                </div>
            </div>
        `);
    }

    openMergeTool() {
        this.showModal('Merge Lists Tool', `
            <div class="tool-content">
                <div class="form-group">
                    <label>First Wordlist</label>
                    <textarea class="form-control" id="mergeList1" rows="4" placeholder="Enter first wordlist..."></textarea>
                </div>
                <div class="form-group">
                    <label>Second Wordlist</label>
                    <textarea class="form-control" id="mergeList2" rows="4" placeholder="Enter second wordlist..."></textarea>
                </div>
                <div class="form-group">
                    <label>Merge Options</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="mergeRemoveDuplicates" checked>
                            <label for="mergeRemoveDuplicates">Remove Duplicates</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="mergeSortOutput">
                            <label for="mergeSortOutput">Sort Output</label>
                        </div>
                    </div>
                </div>
                <div class="modal-actions">
                    <button class="btn-secondary" onclick="wordlistArsenal.closeModal()">Cancel</button>
                    <button class="btn-primary" onclick="wordlistArsenal.applyMerge()">Merge Lists</button>
                </div>
            </div>
        `);
    }

    openRuleTool() {
        this.showModal('Rule Generator Tool', `
            <div class="tool-content">
                <div class="form-group">
                    <label>Rule Type</label>
                    <select class="form-control" id="ruleType">
                        <option value="hashcat">HashCat Rules</option>
                        <option value="john">John the Ripper Rules</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Rule Templates</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="ruleCapitalize" checked>
                            <label for="ruleCapitalize">Capitalize First Letter</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="ruleAppendNumbers" checked>
                            <label for="ruleAppendNumbers">Append Numbers (0-99)</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="ruleAppendSpecial">
                            <label for="ruleAppendSpecial">Append Special Characters</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="ruleReverse">
                            <label for="ruleReverse">Reverse String</label>
                        </div>
                    </div>
                </div>
                <div class="modal-actions">
                    <button class="btn-secondary" onclick="wordlistArsenal.closeModal()">Cancel</button>
                    <button class="btn-primary" onclick="wordlistArsenal.generateRules()">Generate Rules</button>
                </div>
            </div>
        `);
    }

    openStatsTool() {
        this.showModal('Statistics Tool', `
            <div class="tool-content">
                <div class="form-group">
                    <label>Input Wordlist</label>
                    <textarea class="form-control" id="statsInput" rows="6" placeholder="Enter wordlist for analysis..."></textarea>
                </div>
                <div class="modal-actions">
                    <button class="btn-secondary" onclick="wordlistArsenal.closeModal()">Cancel</button>
                    <button class="btn-primary" onclick="wordlistArsenal.analyzeStats()">Analyze</button>
                </div>
                <div id="statsResults" style="margin-top: 1rem;"></div>
            </div>
        `);
    }

    applyFilter() {
        const input = document.getElementById('filterInput')?.value || '';
        const lines = input.split('\n');
        let filtered = lines;
        
        if (document.getElementById('removeEmpty')?.checked) {
            filtered = filtered.filter(line => line.trim());
        }
        
        if (document.getElementById('removeDuplicates')?.checked) {
            filtered = [...new Set(filtered)];
        }
        
        const minLen = parseInt(document.getElementById('minLength')?.value) || 0;
        const maxLen = parseInt(document.getElementById('maxLength')?.value) || Infinity;
        filtered = filtered.filter(line => line.length >= minLen && line.length <= maxLen);
        
        if (document.getElementById('sortAlpha')?.checked) {
            filtered.sort();
        }
        
        this.displayWordlist(filtered, 'Filtered Wordlist');
        this.closeModal();
    }

    applyMerge() {
        const list1 = document.getElementById('mergeList1')?.value.split('\n').filter(l => l.trim()) || [];
        const list2 = document.getElementById('mergeList2')?.value.split('\n').filter(l => l.trim()) || [];
        
        let merged = [...list1, ...list2];
        
        if (document.getElementById('mergeRemoveDuplicates')?.checked) {
            merged = [...new Set(merged)];
        }
        
        if (document.getElementById('mergeSortOutput')?.checked) {
            merged.sort();
        }
        
        this.displayWordlist(merged, 'Merged Wordlist');
        this.closeModal();
    }

    generateRules() {
        const ruleType = document.getElementById('ruleType')?.value || 'hashcat';
        let rules = [];
        
        if (document.getElementById('ruleCapitalize')?.checked) {
            rules.push(ruleType === 'hashcat' ? 'c' : ':');
        }
        
        if (document.getElementById('ruleAppendNumbers')?.checked) {
            for (let i = 0; i < 100; i++) {
                rules.push(ruleType === 'hashcat' ? `$${i}` : `$${i}`);
            }
        }
        
        if (document.getElementById('ruleAppendSpecial')?.checked) {
            const special = ['!', '@', '#', '$', '%', '^', '&', '*'];
            special.forEach(char => {
                rules.push(ruleType === 'hashcat' ? `$${char}` : `$${char}`);
            });
        }
        
        if (document.getElementById('ruleReverse')?.checked) {
            rules.push(ruleType === 'hashcat' ? 'r' : 'r');
        }
        
        this.displayWordlist(rules, `${ruleType.toUpperCase()} Rules`);
        this.closeModal();
    }

    analyzeStats() {
        const input = document.getElementById('statsInput')?.value || '';
        const lines = input.split('\n').filter(l => l.trim());
        const unique = [...new Set(lines)];
        
        const stats = {
            total: lines.length,
            unique: unique.length,
            duplicates: lines.length - unique.length,
            avgLength: lines.length > 0 ? lines.reduce((sum, line) => sum + line.length, 0) / lines.length : 0,
            minLength: lines.length > 0 ? Math.min(...lines.map(l => l.length)) : 0,
            maxLength: lines.length > 0 ? Math.max(...lines.map(l => l.length)) : 0,
            charset: this.analyzeCharset(lines)
        };
        
        const resultsDiv = document.getElementById('statsResults');
        if (resultsDiv) {
            resultsDiv.innerHTML = `
                <div class="stats-display">
                    <h4>Analysis Results</h4>
                    <div class="stat-grid">
                        <div>Total Words: ${stats.total.toLocaleString()}</div>
                        <div>Unique Words: ${stats.unique.toLocaleString()}</div>
                        <div>Duplicates: ${stats.duplicates.toLocaleString()}</div>
                        <div>Average Length: ${stats.avgLength.toFixed(2)}</div>
                        <div>Min Length: ${stats.minLength}</div>
                        <div>Max Length: ${stats.maxLength}</div>
                        <div>Character Set: ${stats.charset}</div>
                    </div>
                </div>
            `;
        }
    }

    analyzeCharset(lines) {
        const hasUpper = lines.some(line => /[A-Z]/.test(line));
        const hasLower = lines.some(line => /[a-z]/.test(line));
        const hasDigits = lines.some(line => /[0-9]/.test(line));
        const hasSpecial = lines.some(line => /[^A-Za-z0-9]/.test(line));
        
        const charset = [];
        if (hasLower) charset.push('lowercase');
        if (hasUpper) charset.push('uppercase');
        if (hasDigits) charset.push('digits');
        if (hasSpecial) charset.push('special');
        
        return charset.join(', ');
    }

    handleFabAction(action) {
        document.getElementById('fab')?.classList.remove('active');
        document.getElementById('fabMenu')?.classList.remove('active');
        
        switch (action) {
            case 'quick-generate':
                this.openQuickGenerate();
                break;
            case 'import':
                document.getElementById('fileInput')?.click();
                break;
            case 'help':
                this.openHelp();
                break;
        }
    }

    openQuickGenerate() {
        this.showModal('Quick Generate', `
            <div class="quick-generate-content">
                <h4>Common Wordlists</h4>
                <div class="quick-options">
                    <button class="btn-primary" onclick="wordlistArsenal.quickGenerate('common-passwords')">
                        <i class="fas fa-key"></i>
                        Common Passwords
                    </button>
                    <button class="btn-primary" onclick="wordlistArsenal.quickGenerate('common-usernames')">
                        <i class="fas fa-user"></i>
                        Common Usernames
                    </button>
                    <button class="btn-primary" onclick="wordlistArsenal.quickGenerate('web-dirs')">
                        <i class="fas fa-folder"></i>
                        Web Directories
                    </button>
                    <button class="btn-primary" onclick="wordlistArsenal.quickGenerate('file-extensions')">
                        <i class="fas fa-file"></i>
                        File Extensions
                    </button>
                </div>
            </div>
        `);
    }

    quickGenerate(type) {
        const wordlists = {
            'common-passwords': ['123456', 'password', 'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'abc123', 'mustang', 'password1', 'qwerty', 'football', 'iloveyou', 'admin123', 'welcome123', 'login', 'master', 'hello', 'freedom', 'whatever'],
            'common-usernames': ['admin', 'administrator', 'user', 'guest', 'test', 'demo', 'root', 'sa', 'oracle', 'postgres', 'mysql', 'ftp', 'mail', 'email', 'web', 'www', 'http', 'ssh', 'support', 'service'],
            'web-dirs': ['admin', 'backup', 'config', 'data', 'files', 'images', 'includes', 'scripts', 'styles', 'uploads', 'downloads', 'documents', 'media', 'assets', 'content', 'public', 'private', 'secure', 'hidden', 'temp'],
            'file-extensions': ['php', 'html', 'htm', 'asp', 'aspx', 'jsp', 'js', 'css', 'txt', 'xml', 'json', 'sql', 'bak', 'old', 'log', 'conf', 'config', 'inc', 'class', 'java']
        };
        
        this.displayWordlist(wordlists[type], `Quick Generate: ${type}`);
        this.closeModal();
    }

    openHelp() {
        this.showModal('Help & Documentation', `
            <div class="help-content">
                <h4>Wordlist Arsenal Guide</h4>
                
                <div class="help-section">
                    <h5><i class="fas fa-cogs"></i> Generators</h5>
                    <p>Use the Generators tab to create custom wordlists. Each generator has specific options and real-time preview.</p>
                </div>
                
                <div class="help-section">
                    <h5><i class="fas fa-search"></i> Analyzer</h5>
                    <p>Upload existing wordlists to analyze their composition, find duplicates, and get detailed statistics.</p>
                </div>
                
                <div class="help-section">
                    <h5><i class="fas fa-wrench"></i> Tools</h5>
                    <p>Use advanced tools to filter, merge, and manipulate wordlists. Generate rules for password crackers.</p>
                </div>
                
                <div class="help-section">
                    <h5><i class="fas fa-download"></i> Export</h5>
                    <p>All generated wordlists can be downloaded as text files or copied to clipboard for immediate use.</p>
                </div>
                
                <div class="help-section">
                    <h5><i class="fas fa-exclamation-triangle"></i> Ethical Use</h5>
                    <p><strong>Important:</strong> This tool is for authorized security testing only. Always ensure you have permission before testing.</p>
                </div>
            </div>
        `);
    }

    showModal(title, content) {
        const modal = document.getElementById('modal');
        const overlay = document.getElementById('modalOverlay');
        
        if (!modal || !overlay) return;
        
        modal.innerHTML = `
            <div class="modal-header">
                <h3>${title}</h3>
                <button class="btn-icon" onclick="wordlistArsenal.closeModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                ${content}
            </div>
        `;
        
        overlay.classList.add('active');
    }

    closeModal() {
        const overlay = document.getElementById('modalOverlay');
        if (overlay) {
            overlay.classList.remove('active');
        }
    }

    showToast(title, message, type = 'info') {
        const container = document.getElementById('toastContainer');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        toast.innerHTML = `
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="btn-icon" onclick="this.parentElement.remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        container.appendChild(toast);
        
        setTimeout(() => toast.classList.add('show'), 100);
        setTimeout(() => toast.remove(), 5000);
    }

    updateStats(generator, count) {
        this.stats.totalGenerated += count;
        this.stats.generatorUsage[generator] = (this.stats.generatorUsage[generator] || 0) + 1;
        
        // Find most used generator
        let mostUsed = 'None';
        let maxUsage = 0;
        for (const [gen, usage] of Object.entries(this.stats.generatorUsage)) {
            if (usage > maxUsage) {
                maxUsage = usage;
                mostUsed = gen;
            }
        }
        this.stats.mostUsed = mostUsed;
        
        this.saveStats();
        this.updateStatsDisplay();
        this.addActivity(`Generated ${count.toLocaleString()} words using ${generator} generator`);
    }

    updateStatsDisplay() {
        const totalGenerated = document.getElementById('totalGenerated');
        const activeSessions = document.getElementById('activeSessions');
        const totalDownloads = document.getElementById('totalDownloads');
        const mostUsed = document.getElementById('mostUsed');
        
        if (totalGenerated) totalGenerated.textContent = this.stats.totalGenerated.toLocaleString();
        if (activeSessions) activeSessions.textContent = this.stats.activeSessions;
        if (totalDownloads) totalDownloads.textContent = this.stats.totalDownloads.toLocaleString();
        if (mostUsed) mostUsed.textContent = this.stats.mostUsed;
    }

    addActivity(message) {
        const activityList = document.getElementById('activityList');
        if (!activityList) return;
        
        const activity = document.createElement('div');
        activity.className = 'activity-item';
        activity.innerHTML = `
            <i class="fas fa-info-circle"></i>
            <span>${message}</span>
            <time>Just now</time>
        `;
        
        activityList.insertBefore(activity, activityList.firstChild);
        
        // Keep only last 10 activities
        while (activityList.children.length > 10) {
            activityList.removeChild(activityList.lastChild);
        }
    }

    saveStats() {
        localStorage.setItem('wordlist_arsenal_stats', JSON.stringify(this.stats));
    }

    saveHistory() {
        localStorage.setItem('wordlist_arsenal_history', JSON.stringify(this.generationHistory));
    }

    loadStats() {
        const saved = localStorage.getItem('wordlist_arsenal_stats');
        if (saved) {
            this.stats = { ...this.stats, ...JSON.parse(saved) };
        }
        
        const savedHistory = localStorage.getItem('wordlist_arsenal_history');
        if (savedHistory) {
            this.generationHistory = JSON.parse(savedHistory);
        }
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    regenerateFromHistory(id) {
        const item = this.generationHistory.find(h => h.id === id);
        if (item) {
            this.switchTab('generators');
            this.switchGenerator(item.generator);
            this.showToast('Info', `Switched to ${item.generator} generator`, 'info');
        }
    }

    deleteHistoryItem(id) {
        this.generationHistory = this.generationHistory.filter(h => h.id !== id);
        this.updateHistoryDisplay();
        this.saveHistory();
        this.showToast('Success', 'History item deleted', 'success');
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.wordlistArsenal = new WordlistArsenal();
});
