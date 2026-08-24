"""
Pipeline Orchestrator - Automated Intelligence Gathering
Automatise la mise à jour des menaces via APScheduler
"""

import schedule
import time
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import sys
import os
import logging

# Force UTF-8 output: on Windows, sys.stdout/stderr default to the system
# codepage (cp1252), which cannot encode the emoji used throughout this
# pipeline's console/log messages and previously crashed run_pipeline()
# before a single scraper could execute.
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/orchestrator.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Créer répertoire logs s'il n'existe pas
Path('logs').mkdir(exist_ok=True)


class PipelineOrchestrator:
    """Orchestration automatique du pipeline de veille"""
    
    def __init__(self, db_path='data/threats.db'):
        self.db_path = db_path
        self.last_run = None
        self.metrics = {
            'total_runs': 0,
            'successful_runs': 0,
            'failed_runs': 0,
            'last_threats_collected': 0,
            'last_run_time': None,
            'next_run_time': None
        }
        self.load_metrics()
    
    def load_metrics(self):
        """Charger les métriques de la dernière session"""
        metrics_file = 'logs/orchestrator_metrics.json'
        if os.path.exists(metrics_file):
            try:
                with open(metrics_file, 'r') as f:
                    self.metrics = json.load(f)
                logger.info(f"📊 Métriques chargées: {self.metrics['total_runs']} exécutions")
            except Exception as e:
                logger.warning(f"Erreur chargement métriques: {e}")
    
    def save_metrics(self):
        """Sauvegarder les métriques"""
        metrics_file = 'logs/orchestrator_metrics.json'
        try:
            with open(metrics_file, 'w') as f:
                json.dump(self.metrics, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Erreur sauvegarde métriques: {e}")
    
    def get_threat_count(self):
        """Obtenir le nombre de menaces en BD"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM threats')
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception as e:
            logger.error(f"Erreur lecture BD: {e}")
            return 0
    
    def run_daily_pipeline(self):
        """Exécute le pipeline quotidien (sources quotidiennes)"""
        logger.info("=" * 70)
        logger.info("🔄 DÉMARRAGE PIPELINE QUOTIDIEN")
        logger.info("=" * 70)
        
        try:
            # Importer et exécuter le pipeline
            from pipeline.process import run_pipeline
            
            threats_before = self.get_threat_count()
            logger.info(f"Menaces avant: {threats_before}")
            
            # Exécuter pipeline
            run_pipeline()
            
            threats_after = self.get_threat_count()
            new_threats = threats_after - threats_before
            
            logger.info(f"Menaces après: {threats_after}")
            logger.info(f"✅ Nouvelles menaces: {new_threats}")
            
            # Mettre à jour métriques
            self.metrics['successful_runs'] += 1
            self.metrics['last_threats_collected'] = new_threats
            self.metrics['last_run_time'] = datetime.now().isoformat()
            
            logger.info("✅ Pipeline quotidien réussi!")
            
        except Exception as e:
            logger.error(f"❌ Erreur pipeline quotidien: {e}")
            self.metrics['failed_runs'] += 1
        
        finally:
            self.metrics['total_runs'] += 1
            self.save_metrics()
    
    def run_weekly_pipeline(self):
        """Exécute le pipeline hebdomadaire (maintenance)"""
        logger.info("=" * 70)
        logger.info("🔄 DÉMARRAGE PIPELINE HEBDOMADAIRE (MAINTENANCE)")
        logger.info("=" * 70)
        
        try:
            # Valider qualité données
            self.validate_data_quality()
            
            # Dédupliquer
            self.deduplicate_threats()
            
            # Générer rapport
            self.generate_weekly_report()
            
            logger.info("✅ Pipeline hebdomadaire réussi!")
            
        except Exception as e:
            logger.error(f"❌ Erreur pipeline hebdomadaire: {e}")
    
    def validate_data_quality(self):
        """Valider la qualité des données"""
        logger.info("🔍 Validation qualité données...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Statistiques
            cursor.execute('SELECT COUNT(*) FROM threats')
            total = cursor.fetchone()[0]
            
            cursor.execute('SELECT threat_type, COUNT(*) FROM threats GROUP BY threat_type')
            by_type = cursor.fetchall()
            
            cursor.execute('SELECT severity, COUNT(*) FROM threats GROUP BY severity')
            by_severity = cursor.fetchall()
            
            conn.close()
            
            logger.info(f"  Total menaces: {total}")
            logger.info(f"  Par type: {dict(by_type)}")
            logger.info(f"  Par sévérité: {dict(by_severity)}")
            
        except Exception as e:
            logger.error(f"  Erreur validation: {e}")
    
    def deduplicate_threats(self):
        """Dédupliquer les menaces"""
        logger.info("🧹 Déduplication menaces...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Trouver et supprimer les doublons (garder le plus récent)
            cursor.execute('''
                DELETE FROM threats 
                WHERE id NOT IN (
                    SELECT MAX(id) FROM threats GROUP BY threat_id
                )
            ''')
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            logger.info(f"  ✅ {deleted} doublons supprimés")
            
        except Exception as e:
            logger.error(f"  Erreur déduplication: {e}")
    
    def generate_weekly_report(self):
        """Générer rapport hebdomadaire"""
        logger.info("📊 Génération rapport hebdomadaire...")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Statistiques
            cursor.execute('SELECT COUNT(*) FROM threats')
            total = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM threats WHERE severity="critical"')
            critical = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM threats WHERE severity="high"')
            high = cursor.fetchone()[0]
            
            cursor.execute('SELECT source, COUNT(*) FROM threats GROUP BY source')
            by_source = cursor.fetchall()
            
            conn.close()
            
            # Créer rapport
            report = {
                'timestamp': datetime.now().isoformat(),
                'total_threats': total,
                'critical': critical,
                'high': high,
                'by_source': dict(by_source)
            }
            
            # Sauvegarder
            with open(f'logs/weekly_report_{datetime.now().strftime("%Y%m%d")}.json', 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"  ✅ Rapport: {total} menaces ({critical} critiques, {high} hautes)")
            
        except Exception as e:
            logger.error(f"  Erreur rapport: {e}")
    
    def get_health_status(self):
        """Obtenir le statut du pipeline"""
        threat_count = self.get_threat_count()
        
        health = {
            'status': '🟢 HEALTHY' if self.metrics['failed_runs'] == 0 else '🟠 WARNING',
            'total_runs': self.metrics['total_runs'],
            'successful': self.metrics['successful_runs'],
            'failed': self.metrics['failed_runs'],
            'success_rate': (self.metrics['successful_runs'] / max(self.metrics['total_runs'], 1) * 100),
            'current_threats': threat_count,
            'last_run': self.metrics.get('last_run_time', 'Never'),
            'last_collected': self.metrics.get('last_threats_collected', 0)
        }
        
        return health
    
    def print_health_status(self):
        """Afficher le statut du pipeline"""
        health = self.get_health_status()
        
        print("\n" + "=" * 70)
        print("📊 PIPELINE ORCHESTRATOR - HEALTH STATUS")
        print("=" * 70)
        print(f"{health['status']}")
        print(f"  Total exécutions: {health['total_runs']}")
        print(f"  Réussies: {health['successful']}")
        print(f"  Échouées: {health['failed']}")
        print(f"  Taux succès: {health['success_rate']:.1f}%")
        print(f"  Menaces en BD: {health['current_threats']}")
        print(f"  Dernière exécution: {health['last_run']}")
        print(f"  Menaces collectées: {health['last_collected']}")
        print("=" * 70 + "\n")


# ============================================
# SCHEDULER AVEC APScheduler
# ============================================

class PipelineScheduler:
    """Gère l'ordonnancement du pipeline"""
    
    def __init__(self):
        self.orchestrator = PipelineOrchestrator()
        self.is_running = False
    
    def schedule_jobs(self):
        """Créer les jobs de planification"""
        
        logger.info("📅 Configuration ordonnancement...")
        
        # QUOTIDIEN 02:00 UTC
        schedule.every().day.at("02:00").do(
            self.orchestrator.run_daily_pipeline
        ).tag('daily')
        logger.info("  ✅ Pipeline quotidien: chaque jour 02:00 UTC")
        
        # HEBDOMADAIRE Lundi 10:00 UTC
        schedule.every().monday.at("10:00").do(
            self.orchestrator.run_weekly_pipeline
        ).tag('weekly')
        logger.info("  ✅ Pipeline hebdomadaire: chaque lundi 10:00 UTC")
        
        # TOUTES LES HEURES : Health check
        schedule.every().hour.do(
            self.orchestrator.print_health_status
        ).tag('health')
        logger.info("  ✅ Health check: chaque heure")
    
    def start(self, test_mode=False):
        """Démarrer l'ordonnancement"""
        logger.info("\n" + "=" * 70)
        logger.info("🚀 DÉMARRAGE PIPELINE ORCHESTRATOR")
        logger.info("=" * 70)
        
        self.orchestrator.print_health_status()
        self.schedule_jobs()
        
        self.is_running = True
        
        if test_mode:
            logger.info("\n⚙️ MODE TEST: Exécution immédiate du pipeline...")
            self.orchestrator.run_daily_pipeline()
            return
        
        logger.info("\n⏱️ En attente des jobs planifiés...")
        logger.info("(Appuyez sur Ctrl+C pour arrêter)\n")
        
        try:
            while self.is_running:
                schedule.run_pending()
                time.sleep(60)  # Vérifier chaque minute
        
        except KeyboardInterrupt:
            logger.info("\n⏸️ Arrêt de l'orchestrateur...")
            self.is_running = False
    
    def stop(self):
        """Arrêter l'ordonnancement"""
        self.is_running = False
        logger.info("✅ Orchestrateur arrêté")


# ============================================
# MAIN
# ============================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Pipeline Orchestrator')
    parser.add_argument('--test', action='store_true', help='Mode test (exécution immédiate)')
    parser.add_argument('--status', action='store_true', help='Afficher statut seulement')
    parser.add_argument('--run-daily', action='store_true', help='Exécuter pipeline quotidien immédiatement')
    parser.add_argument('--run-weekly', action='store_true', help='Exécuter pipeline hebdomadaire immédiatement')
    
    args = parser.parse_args()
    
    orchestrator = PipelineOrchestrator()
    scheduler = PipelineScheduler()
    
    if args.status:
        orchestrator.print_health_status()
    elif args.run_daily:
        orchestrator.run_daily_pipeline()
    elif args.run_weekly:
        orchestrator.run_weekly_pipeline()
    elif args.test:
        scheduler.start(test_mode=True)
    else:
        # Mode normal (démarre l'ordonnancement)
        scheduler.start()
