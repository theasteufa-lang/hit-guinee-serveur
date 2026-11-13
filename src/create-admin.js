import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();
try {
  const email = process.env.ADMIN_EMAIL?.toLowerCase().trim();
  const password = process.env.ADMIN_PASSWORD;
  const phone = process.env.ADMIN_PHONE?.trim();
  if (!email || !password || password.length < 14 || password === 'CHANGE-ME-USE-A-NEW-LONG-PASSWORD') {
    throw new Error('Configure ADMIN_EMAIL et un nouveau ADMIN_PASSWORD de 14 caractères minimum dans .env.');
  }
  const passwordHash = await bcrypt.hash(password, 12);
  const admin = await prisma.user.upsert({
    where: { email },
    update: { passwordHash, phone, role: 'ADMIN', active: true },
    create: { email, phone, passwordHash, role: 'ADMIN', firstName: 'Administrateur' }
  });
  const tasks = [
    ['Connecter un prestataire de paiement marchand','Paiements','Ouvrir un compte marchand, vérifier les frais, pays couverts, webhooks signés et conditions de remboursement.'],
    ['Configurer les paiements Mobile Money par pays','Paiements','Associer uniquement les opérateurs et agrégateurs réellement contractés : Orange Money, MTN MoMo, Wave, Airtel Money, M-Pesa, Moov Money ou autres selon disponibilité.'],
    ['Mettre en place les reversements artistes','Paiements','Valider KYC, comptes de paiement, seuils, frais, calendrier, rapprochement et preuves de paiement.'],
    ['Connecter un fournisseur de stockage audio/vidéo','Technique','Choisir stockage privé, URLs temporaires, limites de taille, antivirus et sauvegardes.'],
    ['Connecter la diffusion audio et vidéo','Technique','Choisir CDN/transcodage, streaming adaptatif, contrôle d’accès et mesure de consommation.'],
    ['Associer une régie publicitaire vidéo','Publicité','Créer un compte éditeur, vérifier l’éligibilité, consentement, inventaire publicitaire et conditions de partage des revenus.'],
    ['Faire relire et valider les contrats artistes','Juridique','Faire vérifier droits d’auteur, licences, durée, territoires, rémunération, résiliation, contenus interdits et litiges.'],
    ['Mettre en place la vérification des artistes','Confiance et sécurité','Définir les pièces nécessaires, consentement, conservation minimale et procédure de contestation.'],
    ['Préparer conformité et protection des données','Juridique','Faire examiner les obligations applicables en Guinée et dans chaque pays d’exploitation.'],
    ['Préparer publication Android','Distribution','Créer compte développeur, politique de confidentialité, tests, signature et fiche Play Store.'],
    ['Configurer support et notifications','Opérations','Associer e-mail/SMS, assistance utilisateurs, alertes techniques et procédure de traitement des incidents.']
  ];
  for (const [title, category, description] of tasks) {
    await prisma.adminTask.upsert({
      where: { id: `seed-${title.toLowerCase().replace(/[^a-z0-9]+/g,'-').slice(0,45)}` },
      update: {},
      create: { id: `seed-${title.toLowerCase().replace(/[^a-z0-9]+/g,'-').slice(0,45)}`, title, category, description }
    }).catch(async () => {
      const exists = await prisma.adminTask.findFirst({ where: { title } });
      if (!exists) await prisma.adminTask.create({ data: { title, category, description } });
    });
  }
  console.log(`Compte administrateur prêt : ${admin.email}`);
} finally {
  await prisma.$disconnect();
}
