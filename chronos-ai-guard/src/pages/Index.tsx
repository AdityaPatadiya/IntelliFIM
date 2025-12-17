import { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useInView } from 'react-intersection-observer';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { 
  Shield, Lock, Eye, Brain, Activity, FileCheck, Network, Bell, 
  BarChart3, Users, Server, Settings, ScrollText, FileText,
  Download, ArrowRight, Github, Linkedin, CheckCircle2,
  TrendingUp, Zap, Globe, AlertTriangle, Mail, Phone, ShieldCheck
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { ThemeToggle } from '@/components/ThemeToggle';
import { ParticleBackground } from '@/components/ParticleBackground';
import { toast } from 'sonner';

const Index = () => {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();
  const [heroStats, setHeroStats] = useState({ monitored: 0, detected: 0, prevented: 0 });
  const [stats, setStats] = useState({ monitored: 0, detected: 0, prevented: 0 });
  const [scrollY, setScrollY] = useState(0);

  const [formData, setFormData] = useState({
    name: '',
    email: '',
    message: ''
  });

  // Intersection observers for scroll animations
  const [heroRef, heroInView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [highlightsRef, highlightsInView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [aboutRef, aboutInView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [archRef, archInView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [statsRef, statsInView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [dashboardRef, dashboardInView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [contactRef, contactInView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [modulesRef, modulesInView] = useInView({ triggerOnce: true, threshold: 0.1 });
  const [useCasesRef, useCasesInView] = useInView({ triggerOnce: true, threshold: 0.1 });

  // Parallax scroll effect
  useEffect(() => {
    const handleScroll = () => setScrollY(window.scrollY);
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard');
    }
  }, [isAuthenticated, navigate]);

  // Animated counters for HERO section - triggers immediately when hero is visible
  useEffect(() => {
    if (!heroInView) return;

    const duration = 2000;
    const steps = 60;
    const interval = duration / steps;
    const targets = { monitored: 15847, detected: 1243, prevented: 892 };

    let step = 0;
    const timer = setInterval(() => {
      step++;
      setHeroStats({
        monitored: Math.floor((targets.monitored / steps) * step),
        detected: Math.floor((targets.detected / steps) * step),
        prevented: Math.floor((targets.prevented / steps) * step)
      });
      if (step >= steps) {
        clearInterval(timer);
        setHeroStats(targets);
      }
    }, interval);

    return () => clearInterval(timer);
  }, [heroInView]);

  // Animated counters for STATS section
  useEffect(() => {
    if (!statsInView) return;

    const duration = 2000;
    const steps = 60;
    const interval = duration / steps;
    const targets = { monitored: 15847, detected: 1243, prevented: 892 };

    let step = 0;
    const timer = setInterval(() => {
      step++;
      setStats({
        monitored: Math.floor((targets.monitored / steps) * step),
        detected: Math.floor((targets.detected / steps) * step),
        prevented: Math.floor((targets.prevented / steps) * step)
      });
      if (step >= steps) {
        clearInterval(timer);
        setStats(targets);
      }
    }, interval);

    return () => clearInterval(timer);
  }, [statsInView]);

  const handleContactSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    toast.success('Message sent! We\'ll get back to you soon.');
    setFormData({ name: '', email: '', message: '' });
  };

  const modules = [
    { title: 'Dashboard', icon: BarChart3, description: 'Unified security overview', href: '/dashboard' },
    { title: 'File Monitoring', icon: FileCheck, description: 'Real-time integrity checks', href: '/file-integrity' },
    { title: 'Network Monitoring', icon: Network, description: 'Traffic analysis & detection', href: '/network-monitoring' },
    { title: 'AI Anomaly Detection', icon: Brain, description: 'ML-powered threat detection', href: '/ai-anomaly' },
    { title: 'Incident Management', icon: AlertTriangle, description: 'Response & mitigation', href: '/incidents' },
    { title: 'Employee Management', icon: Users, description: 'Access control & roles', href: '/employees' },
    { title: 'System Configuration', icon: Settings, description: 'Platform settings', href: '/config' },
    { title: 'Reports & Analytics', icon: FileText, description: 'Compliance & insights', href: '/reports' },
    { title: 'Logs & Audit', icon: ScrollText, description: 'Activity tracking', href: '/logs' },
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="text-xl font-bold">IntelliFIM</span>
          </div>
          <div className="flex items-center gap-4">
            <ThemeToggle />
            <Button variant="ghost" onClick={() => navigate('/auth')}>Sign In</Button>
            <Button onClick={() => navigate('/auth')}>Get Started</Button>
          </div>
        </div>
      </header>

      {/* Hero Section with Particle Background */}
      <section ref={heroRef} className="relative overflow-hidden px-4 py-24 lg:py-32 min-h-[90vh] flex items-center">
        <ParticleBackground />
        <div 
          className="absolute inset-0 bg-gradient-to-br from-primary/10 via-accent/5 to-background -z-10"
          style={{ transform: `translateY(${scrollY * 0.3}px)` }}
        />
        {/* Floating orbs with parallax */}
        <div 
          className="absolute top-20 left-10 w-72 h-72 bg-primary/20 rounded-full blur-3xl -z-10"
          style={{ transform: `translate(${scrollY * 0.1}px, ${scrollY * 0.2}px)` }}
        />
        <div 
          className="absolute bottom-20 right-10 w-96 h-96 bg-accent/15 rounded-full blur-3xl -z-10"
          style={{ transform: `translate(${-scrollY * 0.15}px, ${scrollY * 0.1}px)` }}
        />
        <div className="container mx-auto max-w-7xl">
          <div className="grid gap-12 lg:grid-cols-[1fr,420px] lg:gap-16 items-center">
            <div 
              className={`space-y-8 transition-all duration-1000 ${heroInView ? 'opacity-100 translate-x-0' : 'opacity-0 -translate-x-10'}`}
              style={{ transform: `translateY(${scrollY * -0.05}px)` }}
            >
              <Badge variant="secondary" className="w-fit animate-pulse">
                <Zap className="mr-1 h-3 w-3" />
                Enterprise-Grade Security
              </Badge>
              <h1 className="text-4xl font-bold tracking-tight lg:text-6xl bg-gradient-to-r from-foreground via-primary to-accent bg-clip-text text-transparent">
                AI-Driven File Integrity & Intrusion Prevention
              </h1>
              <p className="text-xl text-muted-foreground">
                Next-generation security monitoring that combines file integrity, network analysis, and AI-powered anomaly detection to protect your enterprise infrastructure.
              </p>
              <div className="flex flex-wrap gap-4">
                <Button size="lg" className="group relative overflow-hidden" onClick={() => navigate('/auth')}>
                  <span className="relative z-10">Access Dashboard</span>
                  <ArrowRight className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1 relative z-10" />
                  <div className="absolute inset-0 bg-gradient-to-r from-primary to-accent opacity-0 group-hover:opacity-100 transition-opacity" />
                </Button>
                <Button size="lg" variant="outline" className="group">
                  <Download className="mr-2 h-4 w-4 group-hover:animate-bounce" />
                  Download Agent
                </Button>
              </div>
            </div>

            <div 
              className={`space-y-4 transition-all duration-1000 delay-300 ${heroInView ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-10'}`}
              style={{ transform: `translateY(${scrollY * -0.08}px)` }}
            >
              <Card className="border-border bg-card/50 backdrop-blur hover:scale-105 transition-transform duration-300 hover:border-primary/50">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Active Agents</CardTitle>
                  <ShieldCheck className="h-5 w-5 text-primary animate-pulse" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold">{heroStats.monitored.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    <span className="text-success">↑ +12%</span> from last week
                  </p>
                </CardContent>
              </Card>
              
              <Card className="border-border bg-card/50 backdrop-blur hover:scale-105 transition-transform duration-300 hover:border-destructive/50">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Threats Detected</CardTitle>
                  <AlertTriangle className="h-5 w-5 text-destructive" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold">{heroStats.detected.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    <span className="text-success">↑ +3</span> from last week
                  </p>
                </CardContent>
              </Card>
              
              <Card className="border-border bg-card/50 backdrop-blur hover:scale-105 transition-transform duration-300 hover:border-success/50">
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Prevention Actions</CardTitle>
                  <Zap className="h-5 w-5 text-success" />
                </CardHeader>
                <CardContent>
                  <div className="text-3xl font-bold">{heroStats.prevented.toLocaleString()}</div>
                  <p className="text-xs text-muted-foreground mt-1">
                    <span className="text-success">↓ -2</span> from last week
                  </p>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </section>

      {/* Key Highlights */}
      <section ref={highlightsRef} className="px-4 py-16 bg-muted/30 relative overflow-hidden">
        <div 
          className="absolute inset-0 bg-gradient-to-r from-primary/5 to-accent/5 -z-10"
          style={{ transform: `translateX(${scrollY * 0.1}px)` }}
        />
        <div className="container mx-auto max-w-6xl">
          <div className={`grid gap-8 md:grid-cols-2 lg:grid-cols-4 transition-all duration-1000 ${highlightsInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            {[
              { icon: FileCheck, title: 'File Monitoring', desc: 'Real-time integrity validation' },
              { icon: Network, title: 'Network Analysis', desc: 'Traffic pattern recognition' },
              { icon: Brain, title: 'AI Threat Detection', desc: 'Machine learning powered' },
              { icon: Zap, title: 'Automated Response', desc: 'Instant threat mitigation' }
            ].map((item, i) => (
              <Card 
                key={i} 
                className="border-border/50 hover:border-primary/50 transition-all duration-500 hover:scale-105 hover:-translate-y-2 hover:shadow-xl hover:shadow-primary/10"
                style={{ 
                  transitionDelay: `${i * 100}ms`,
                  opacity: highlightsInView ? 1 : 0,
                  transform: highlightsInView ? 'translateY(0)' : 'translateY(20px)'
                }}
              >
                <CardHeader>
                  <div className="relative">
                    <item.icon className="h-10 w-10 text-primary mb-2 transition-transform duration-300 group-hover:scale-110" />
                    <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full opacity-0 hover:opacity-100 transition-opacity" />
                  </div>
                  <CardTitle className="text-lg">{item.title}</CardTitle>
                  <CardDescription>{item.desc}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* About Section */}
      <section ref={aboutRef} className="px-4 py-20">
        <div className={`container mx-auto max-w-4xl text-center space-y-6 transition-all duration-1000 ${aboutInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          <Badge variant="outline">About IntelliFIM</Badge>
          <h2 className="text-3xl font-bold lg:text-4xl">
            Next-Generation Enterprise Security
          </h2>
          <p className="text-lg text-muted-foreground leading-relaxed">
            With the increasing sophistication of cyber threats, traditional File Integrity Monitoring (FIM) and Intrusion Detection Systems (IDS) often struggle to provide real-time, context-aware protection. IntelliFIM presents an innovative AI-driven Intrusion Prevention System integrated with comprehensive file monitoring, designed to provide proactive security for enterprise environments.
          </p>
          <p className="text-lg text-muted-foreground leading-relaxed">
            The system correlates file-level events with network behavior, evaluates risk based on user role, device, location, and temporal patterns, assigning a dynamic threat score. It executes tiered response strategies including session isolation, alert generation, and administrative approval, reducing false positives while ensuring operational continuity.
          </p>
          <div className="grid gap-4 md:grid-cols-3 pt-8">
            {[
              { icon: CheckCircle2, text: 'Context-Aware Detection' },
              { icon: CheckCircle2, text: 'Explainable AI (XAI)' },
              { icon: CheckCircle2, text: 'Automated Compliance' }
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-2 justify-center">
                <item.icon className="h-5 w-5 text-accent" />
                <span className="font-medium">{item.text}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* System Architecture */}
      <section ref={archRef} className="px-4 py-20 bg-muted/30">
        <div className="container mx-auto max-w-6xl">
          <div className={`text-center mb-12 transition-all duration-1000 ${archInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <h2 className="text-3xl font-bold mb-4">System Architecture</h2>
            <p className="text-muted-foreground">Enterprise-grade infrastructure designed for scale and reliability</p>
          </div>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            {[
              { icon: Download, title: 'Local Agent', desc: 'Lightweight monitoring client for Windows, Linux, and macOS' },
              { icon: Server, title: 'Python Backend', desc: 'High-performance API and data processing engine' },
              { icon: Globe, title: 'React Interface', desc: 'Modern, responsive web dashboard' },
              { icon: Shield, title: 'Admin Control', desc: 'Centralized security management and policy enforcement' }
            ].map((item, i) => (
              <Card key={i} className="text-center">
                <CardHeader>
                  <div className="mx-auto rounded-full bg-primary/10 p-4 w-fit mb-4">
                    <item.icon className="h-8 w-8 text-primary" />
                  </div>
                  <CardTitle className="text-lg">{item.title}</CardTitle>
                  <CardDescription>{item.desc}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Live Stats */}
      <section ref={statsRef} className="px-4 py-20">
        <div className="container mx-auto max-w-6xl">
          <div className={`text-center mb-12 transition-all duration-1000 ${statsInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <Badge variant="secondary" className="mb-4">
              <TrendingUp className="mr-1 h-3 w-3" />
              Real-Time Performance
            </Badge>
            <h2 className="text-3xl font-bold">Security Metrics</h2>
          </div>
          <div className={`grid gap-8 md:grid-cols-3 transition-all duration-1000 delay-300 ${statsInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <Card className="text-center border-primary/20">
              <CardHeader>
                <CardTitle className="text-5xl font-bold text-primary">{stats.monitored.toLocaleString()}</CardTitle>
                <CardDescription className="text-base">Files Monitored</CardDescription>
              </CardHeader>
            </Card>
            <Card className="text-center border-accent/20">
              <CardHeader>
                <CardTitle className="text-5xl font-bold text-accent">{stats.detected.toLocaleString()}</CardTitle>
                <CardDescription className="text-base">Anomalies Detected</CardDescription>
              </CardHeader>
            </Card>
            <Card className="text-center border-destructive/20">
              <CardHeader>
                <CardTitle className="text-5xl font-bold text-destructive">{stats.prevented.toLocaleString()}</CardTitle>
                <CardDescription className="text-base">Intrusions Prevented</CardDescription>
              </CardHeader>
            </Card>
          </div>
        </div>
      </section>

      {/* Core Modules */}
      <section ref={modulesRef} className="px-4 py-20 bg-muted/30 relative overflow-hidden">
        <div 
          className="absolute top-0 right-0 w-96 h-96 bg-primary/10 rounded-full blur-3xl -z-10"
          style={{ transform: `translate(${scrollY * 0.05}px, ${-scrollY * 0.1}px)` }}
        />
        <div className="container mx-auto max-w-6xl">
          <div className={`text-center mb-12 transition-all duration-1000 ${modulesInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <h2 className="text-3xl font-bold mb-4">Core Security Modules</h2>
            <p className="text-muted-foreground">Comprehensive suite of enterprise security tools</p>
          </div>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {modules.map((module, i) => (
              <Card 
                key={i} 
                className="group hover:border-primary/50 transition-all duration-500 cursor-pointer hover:scale-105 hover:-translate-y-2 hover:shadow-xl hover:shadow-primary/10" 
                onClick={() => navigate('/auth')}
                style={{ 
                  transitionDelay: `${i * 50}ms`,
                  opacity: modulesInView ? 1 : 0,
                  transform: modulesInView ? 'translateY(0)' : 'translateY(20px)'
                }}
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="relative">
                      <module.icon className="h-10 w-10 text-primary group-hover:scale-110 transition-transform duration-300" />
                      <div className="absolute inset-0 bg-primary/30 blur-xl rounded-full opacity-0 group-hover:opacity-100 transition-opacity" />
                    </div>
                    <ArrowRight className="h-5 w-5 text-muted-foreground group-hover:translate-x-2 group-hover:text-primary transition-all duration-300" />
                  </div>
                  <CardTitle className="mt-4 group-hover:text-primary transition-colors">{module.title}</CardTitle>
                  <CardDescription>{module.description}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Download & Deployment */}
      <section className="px-4 py-20">
        <div className="container mx-auto max-w-4xl">
          <Card className="border-primary/20">
            <CardHeader className="text-center">
              <CardTitle className="text-3xl mb-4">Download & Deploy</CardTitle>
              <CardDescription className="text-base">
                Get started with IntelliFIM in minutes. Download the agent for your platform.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid gap-4 md:grid-cols-3">
                <Button variant="outline" size="lg" className="h-20">
                  <div className="text-center">
                    <Download className="h-6 w-6 mx-auto mb-2" />
                    <div className="font-semibold">Windows</div>
                  </div>
                </Button>
                <Button variant="outline" size="lg" className="h-20">
                  <div className="text-center">
                    <Download className="h-6 w-6 mx-auto mb-2" />
                    <div className="font-semibold">Linux</div>
                  </div>
                </Button>
                <Button variant="outline" size="lg" className="h-20">
                  <div className="text-center">
                    <Download className="h-6 w-6 mx-auto mb-2" />
                    <div className="font-semibold">macOS</div>
                  </div>
                </Button>
              </div>
              <div className="rounded-lg border border-border bg-muted/50 p-6">
                <h4 className="font-semibold mb-3">Quick Installation</h4>
                <ol className="list-decimal list-inside space-y-2 text-sm text-muted-foreground">
                  <li>Download the appropriate agent for your operating system</li>
                  <li>Run the installer with administrator privileges</li>
                  <li>Configure the API endpoint in the agent settings</li>
                  <li>Start monitoring and view results in the dashboard</li>
                </ol>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Use Cases */}
      <section ref={useCasesRef} className="px-4 py-20 bg-muted/30 relative overflow-hidden">
        <div 
          className="absolute bottom-0 left-0 w-80 h-80 bg-accent/10 rounded-full blur-3xl -z-10"
          style={{ transform: `translate(${-scrollY * 0.05}px, ${scrollY * 0.08}px)` }}
        />
        <div className="container mx-auto max-w-6xl">
          <div className={`text-center mb-12 transition-all duration-1000 ${useCasesInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <h2 className="text-3xl font-bold mb-4">Use Cases</h2>
            <p className="text-muted-foreground">Trusted by organizations across industries</p>
          </div>
          <div className="grid gap-8 md:grid-cols-3">
            {[
              { icon: Server, title: 'Enterprises', desc: 'Comprehensive security monitoring for large-scale infrastructure with compliance reporting and advanced threat detection capabilities.' },
              { icon: Globe, title: 'MSMEs', desc: 'Affordable, easy-to-deploy security solution for small and medium businesses requiring enterprise-grade protection without complexity.' },
              { icon: Shield, title: 'Security Teams', desc: 'Advanced SOC tools with real-time alerting, incident response automation, and detailed forensic analysis capabilities.' }
            ].map((item, i) => (
              <Card 
                key={i}
                className="hover:scale-105 hover:-translate-y-2 transition-all duration-500 hover:shadow-xl hover:shadow-primary/10"
                style={{ 
                  transitionDelay: `${i * 100}ms`,
                  opacity: useCasesInView ? 1 : 0,
                  transform: useCasesInView ? 'translateY(0)' : 'translateY(20px)'
                }}
              >
                <CardHeader>
                  <div className="relative w-fit">
                    <item.icon className="h-10 w-10 text-primary mb-4" />
                    <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full" />
                  </div>
                  <CardTitle>{item.title}</CardTitle>
                  <CardDescription>{item.desc}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Dashboard Preview */}
      <section ref={dashboardRef} className="px-4 py-20">
        <div className="container mx-auto max-w-6xl">
          <div className={`text-center mb-12 transition-all duration-1000 ${dashboardInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <Badge variant="secondary" className="mb-4">
              <Eye className="mr-1 h-3 w-3" />
              Live Preview
            </Badge>
            <h2 className="text-3xl font-bold mb-4">Powerful Dashboard Interface</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Real-time monitoring, intelligent analytics, and actionable insights all in one unified interface
            </p>
          </div>
          <div className={`transition-all duration-1000 delay-300 ${dashboardInView ? 'opacity-100 scale-100' : 'opacity-0 scale-95'}`}>
            <Card className="border-primary/20 overflow-hidden">
              <CardContent className="p-0">
                <div className="bg-gradient-to-br from-primary/10 via-accent/5 to-background p-8">
                  <div className="bg-card rounded-lg border border-border p-6 space-y-6">
                    {/* Mini Dashboard Preview */}
                    <div className="grid gap-4 md:grid-cols-4">
                      <div className="bg-background rounded-lg p-4 border border-border">
                        <div className="flex items-center gap-2 mb-2">
                          <ShieldCheck className="h-4 w-4 text-primary" />
                          <span className="text-xs text-muted-foreground">Active Agents</span>
                        </div>
                        <p className="text-2xl font-bold">24</p>
                      </div>
                      <div className="bg-background rounded-lg p-4 border border-border">
                        <div className="flex items-center gap-2 mb-2">
                          <AlertTriangle className="h-4 w-4 text-primary" />
                          <span className="text-xs text-muted-foreground">Threats</span>
                        </div>
                        <p className="text-2xl font-bold">12</p>
                      </div>
                      <div className="bg-background rounded-lg p-4 border border-border">
                        <div className="flex items-center gap-2 mb-2">
                          <FileCheck className="h-4 w-4 text-primary" />
                          <span className="text-xs text-muted-foreground">Files Monitored</span>
                        </div>
                        <p className="text-2xl font-bold">4,231</p>
                      </div>
                      <div className="bg-background rounded-lg p-4 border border-border">
                        <div className="flex items-center gap-2 mb-2">
                          <Zap className="h-4 w-4 text-primary" />
                          <span className="text-xs text-muted-foreground">Prevention Actions</span>
                        </div>
                        <p className="text-2xl font-bold">8</p>
                      </div>
                    </div>
                    <div className="bg-background rounded-lg p-4 border border-border">
                      <p className="text-sm font-medium mb-4">Threat Trends</p>
                      <div className="h-32 flex items-end gap-2">
                        {[20, 35, 25, 45, 70, 55, 90, 75, 60, 85].map((height, i) => (
                          <div key={i} className="flex-1 bg-primary/20 rounded-t" style={{ height: `${height}%` }} />
                        ))}
                      </div>
                    </div>
                    <Button className="w-full" onClick={() => navigate('/auth')}>
                      View Full Dashboard
                      <ArrowRight className="ml-2 h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      {/* Contact Form */}
      <section ref={contactRef} className="px-4 py-20 bg-muted/30">
        <div className="container mx-auto max-w-2xl">
          <div className={`text-center mb-12 transition-all duration-1000 ${contactInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <Badge variant="secondary" className="mb-4">
              <Mail className="mr-1 h-3 w-3" />
              Get in Touch
            </Badge>
            <h2 className="text-3xl font-bold mb-4">Contact Us</h2>
            <p className="text-muted-foreground">
              Have questions? We'd love to hear from you. Send us a message and we'll respond as soon as possible.
            </p>
          </div>
          <Card className={`transition-all duration-1000 delay-300 ${contactInView ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
            <CardContent className="pt-6">
              <form onSubmit={handleContactSubmit} className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="name">Name</Label>
                  <Input 
                    id="name" 
                    placeholder="Your name" 
                    value={formData.name}
                    onChange={(e) => setFormData({...formData, name: e.target.value})}
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <Input 
                    id="email" 
                    type="email" 
                    placeholder="your.email@example.com" 
                    value={formData.email}
                    onChange={(e) => setFormData({...formData, email: e.target.value})}
                    required
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="message">Message</Label>
                  <Textarea 
                    id="message" 
                    placeholder="Your message..." 
                    rows={5}
                    value={formData.message}
                    onChange={(e) => setFormData({...formData, message: e.target.value})}
                    required
                  />
                </div>
                <Button type="submit" className="w-full">
                  <Mail className="mr-2 h-4 w-4" />
                  Send Message
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border bg-muted/30 px-4 py-12">
        <div className="container mx-auto max-w-6xl">
          <div className="grid gap-8 md:grid-cols-4">
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <Shield className="h-6 w-6 text-primary" />
                <span className="text-xl font-bold">IntelliFIM</span>
              </div>
              <p className="text-sm text-muted-foreground">
                AI-Driven File Integrity & Intrusion Prevention System
              </p>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><button onClick={() => navigate('/auth')} className="hover:text-foreground transition-colors">Features</button></li>
                <li><button onClick={() => navigate('/auth')} className="hover:text-foreground transition-colors">Dashboard</button></li>
                <li><button onClick={() => navigate('/auth')} className="hover:text-foreground transition-colors">Documentation</button></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Resources</h4>
              <ul className="space-y-2 text-sm text-muted-foreground">
                <li><a href="https://github.com/AdityaPatadiya/IntelliFIM" target="_blank" rel="noopener noreferrer" className="hover:text-foreground transition-colors">GitHub</a></li>
                <li><button className="hover:text-foreground transition-colors">API Docs</button></li>
                <li><button className="hover:text-foreground transition-colors">Support</button></li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-4">Connect</h4>
              <div className="flex gap-4">
                <a 
                  href="https://github.com/AdityaPatadiya/IntelliFIM" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="rounded-full border border-border p-2 hover:border-primary transition-colors"
                >
                  <Github className="h-5 w-5" />
                </a>
                <a 
                  href="https://www.linkedin.com/in/aditya-patadiya-5356a3247/" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="rounded-full border border-border p-2 hover:border-primary transition-colors"
                >
                  <Linkedin className="h-5 w-5" />
                </a>
              </div>
            </div>
          </div>
          <div className="mt-12 pt-8 border-t border-border text-center text-sm text-muted-foreground">
            <p>© 2025 IntelliFIM. All rights reserved. Built with advanced AI and security principles.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
