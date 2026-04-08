// Premium Ghost Experience JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Add floating ghost elements dynamically
    const ghostPositions = [
        { top: '5%', left: '3%', delay: 0 },
        { top: '85%', left: '92%', delay: 2 },
        { top: '20%', left: '95%', delay: 4 },
        { top: '70%', left: '2%', delay: 1 },
        { top: '45%', left: '88%', delay: 3 }
    ];

    ghostPositions.forEach(pos => {
        const ghost = document.createElement('div');
        ghost.className = 'floating-ghost';
        ghost.style.top = pos.top;
        ghost.style.left = pos.left;
        ghost.style.animationDelay = `${pos.delay}s`;
        ghost.innerHTML = ['👻', '🕯️', '✨', '🌙', '⭐'][Math.floor(Math.random() * 5)];
        document.body.appendChild(ghost);
    });

    // Animate form inputs on focus
    document.querySelectorAll('.premium-input').forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('focused');
        });
    });

    // Add haptic feedback on button click
    document.querySelectorAll('.premium-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            this.style.transform = 'scale(0.98)';
            setTimeout(() => {
                this.style.transform = '';
            }, 150);
        });
    });
});

// ─── Rotating facts (email page) ──────────────────────────────────────────────
if (document.getElementById('funFactText')) {
    const facts = [
        { icon: "🏪", title: "GHOST MARKET", text: "The first anonymous marketplace built into a messaging platform. Sell used items without anyone knowing who you are." },
        { icon: "🔑", title: "ZEUS-PIN", text: "Your identity is your PIN. No phone number needed. Ever. No tracking. No spam." },
        { icon: "💀", title: "SELF-DESTRUCT", text: "Messages disappear after a set timer. No saving. No screenshots. No traces." },
        { icon: "👻", title: "GHOST TOWN", text: "Posts vanish after 24 hours. What happens in Ghost Town stays in Ghost Town." },
        { icon: "💰", title: "GET PAID", text: "Earn 80% of every paid post. Your content, your value, your earnings." },
        { icon: "🌍", title: "YOUR LANGUAGE", text: "Speak Swahili, Yoruba, Zulu, Hausa, Igbo, or Amharic. ZeusChat speaks YOUR language." }
    ];

    let factIndex = 0;

    function rotateFact() {
        const fact = facts[factIndex];
        const iconEl = document.getElementById('funFactIcon');
        const titleEl = document.getElementById('funFactTitle');
        const textEl = document.getElementById('funFactText');

        if (iconEl) iconEl.textContent = fact.icon;
        if (titleEl) titleEl.textContent = fact.title;
        if (textEl) textEl.innerHTML = fact.text;

        factIndex = (factIndex + 1) % facts.length;
    }

    rotateFact();
    setInterval(rotateFact, 8000);
}

// ─── Live population counter (OTP page) ───────────────────────────────────────
if (document.getElementById('populationCount')) {
    let population = 12437;
    document.getElementById('populationCount').textContent = population.toLocaleString();
    setInterval(() => {
        population += Math.floor(Math.random() * 5) + 1;
        document.getElementById('populationCount').textContent = population.toLocaleString();
    }, 30000);
}
