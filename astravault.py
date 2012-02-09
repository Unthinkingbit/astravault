#!/usr/bin/python
"""
Astravault is a program to encrypt the bitcoin wallet, email it to yourself to back it up and decrypt it if necessary.

The outgoing mail default subject is the bland 'Astronomy Data', to make the email innocuous.

==Install==
For astravault to run, you need Python 2.x, astravault will probably not run with python 3.x.  To check if it is on your machine, in a terminal type:
python

If python 2.x is not on your machine, download the latest python 2.x, which is available from:
http://www.python.org/download/

You will also need OpenSSL.  To check if it is on your machine, type:
openssl

If it is not on your machine, the openssl home page is at:
http://www.openssl.org/

==Set up==
When astravault is set up, calling 'python astravault.py' will encrypt the bitcoin wallet and email to you.

To set up astravault, first get the name of the outgoing SMTP mail server of your isp, it is usually something like mail.myisp.com.  You can usually find the name of the mail server on the isp web site, and there is also a list of SMTP outgoing mail servers for several internet service providers at:
http://www.realifewebdesigns.com/web-resources/pop3-smtp.html

Then, if you are not using your isp mail, for instance if you are using webmail like gmail, get the name of your email address at your isp.

Once you have your isp email address and the name of you outgoing mail server, you can set the parameters with the command line or with a spreadsheet program.

To set up astravault with the command line, type:
python astravault.py -f myname@myisp.com -ma mail.myisp.com -t myemail@mywebmail.com

If you prefer to set up astravault with a spreadsheet, type:
python astravault.py -pr

This will save and print the settings.  Then open the settings file at:
<your home directory>/settings/astravault/astravault.csv

with a spreadsheet using the <tab> separator options.  Then set the Email From, Email To and Mail Server fields.

==Commands==
If astravault is called without any options, it will encrypt and mail the wallet.  This is the same as if it is called with only the -em (encrypt & mail) option.  For the mail to work, the mail settings must be set.  The example follows:
python astravault.py

===Decrypt===
Adding the -d option will command astravault to decrypt a file.  This can be used to decrypt the backup after downloading.  If a wallet is not in the bitcoin folder, if for example astravault shredded it, then the decrypted wallet will be moved to the original location in the bitcoin folder.  The example follows:
python astravault.py -d

===Encrypt===
Adding the -e option will command astravault to encrypt the wallet.  The example follows:
python astravault.py -e

===Encrypt and Mail===
Adding the -em option will command astravault to encrypt the wallet and mail it.  The example follows:
python astravault.py -em

===Encrypt, Mail and Shred===
Adding the -emshred option will command astravault to encrypt the wallet, mail it, then shred it.  To later recreate the wallet, use the -d option to decrypt and move the decrypted wallet to the original location in the bitcoin folder.  The example follows:
python astravault.py -emshred

===Help===
Adding the -h option will print the help, which is this document.  The example follows:
python astravault.py -h

===Mail===
Adding the -m option will mail the wallet, assuming it has already been moved into the astravault directory.  The example follows:
python astravault.py -m

===Print Variables===
Adding the -pr option will print the astravault variables.  The example follows:
python astravault.py -pr

===Toggle===
Adding the -toggle option will toggle the wallet between its encrypted state and its original state.   If there is a bitcoin wallet, choosing toggle will encrypt the bitcoin wallet, mail it, then shred it; otherwise the wallet will be decrypted and moved its original locations.  The toggle option is useful to prevent a thief who stole your computer from using the bitcoins on your computer.  The example follows:
python astravault.py -toggle

==Mail Settings==
The 'Email From', 'Email To' & 'Mail Server' mail settings are empty by default, you must set them in order to send mail.  The Port has a default setting of 25, which works for many mail servers, but you may have to change it for your isp.

===Attachment Name===
The default is galileo.astr.

The -a option sets the 'Attachment Name'.  For example, to change the attachment name to generic.foo, type:
python astravault.py -a generic.foo

===Email From===
The default is empty, this must be set to send email.

The -f option sets the 'Email From' address, the email will be sent from this address.  The address must be your isp email address.  For example, to change the 'Email From' address to me@myisp.com, type:
python astravault.py -f me@myisp.com

===Email To===
The default is empty, this must be set to send email.

The -t option sets the 'Email To' address, the email will be sent to this address.  If the address is a comma separated string, the email will be sent to all the recipients on the list.  The address can be any valid email address, it can your your isp email address or a webmail address.  For example, to change the 'Email To' address to me@mywebmail.com, type:
python astravault.py -t me@mywebmail.com

===Mail Server===
The default is empty, this must be set to send email.

The -ma option sets the 'Mail Server' name, which should be the name of the outgoing SMTP mail server of your isp, it is usually something like mail.myisp.com.  You can usually find the name of the mail server on the isp web site.  For example, to change the 'Mail Server' name to mail.myisp.com, type:
python astravault.py -ma mail.myisp.com

===Message Body===
The default is 'Astronomy data from Galileo observatory.'

The -me option sets the email 'Message Body'.  For example, to change the message body to 'Generic data.', type:
python astravault.py -me 'Generic data.'

===Port===
The default is 25.

The -po option sets the mail server 'Port'.  For example, to change the mail server port to 465, type:
python astravault.py -po '465.'

===Subject===
The default is 'Astronomy Data'.

The -s option sets the email 'Subject'.  For example, to change the subject to 'Generic Subject', type:
python astravault.py -s 'Generic Subject'

==Wallet Settings==
The wallet settings are set to encrypt the bitcoin wallet in the home directory.

===Permanent Password===
The default is empty

The -permanent option sets the 'Permanent Password'.  Because this is visible on screen when typed, and because the password is permanent, this should only be used if a person is certain that they are not being watched, for example if they are home alone.  This is a convience so that a person can make a really long and complicated password, write it down somewhere secure, and then call astravault without having to enter the password each time.  If the permanent password is shorter than eight characters, it will be ignored and the user will be asked for another password.  For example, to change the permanent password to reallyLongComplicatedPasswordWithLotsOf$ymbol$AndNumbers1236826347897856, type:
python astravault.py -permanent reallyLongComplicatedPasswordWithLotsOf$ymbol$AndNumbers1236826347897856

===Temporary Password===
The default is empty

The -te option sets the 'Temporary Password'.  Because this is visible on screen when typed, this should only be used by a program calling astravault.  When a person uses astravault, the password will be asked for by the get password function which does not show the password on screen.

For programs that want to use a temporary password, call astravault like so:
python astravault.py -te mytemporarypassword

===Wallet Path===
The default is <your home directory>/.bitcoin/wallet.dat

The -w option sets the 'Wallet Path'.  The default is the bitcoin wallet, but it can be set to encrypt and mail any file.  For example, to change the wallet path to myspreadsheet.csv, type:
python astravault.py -w myspreadsheet.csv

"""

from __future__ import absolute_import
import __init__

import base64
import binascii
import cStringIO
import getpass
import os
import random
import shutil
import smtplib
import subprocess
import sys
import time


__license__ = 'GPL http://www.gnu.org/licenses/gpl.html'


# switch m & ma, add warning when mail is blank


def getEncodedBinary(fileName, printWarning=True, readMode='rb'):
	'Get the entire text of a binary file encoded in base64.'
	text = getFileText(fileName, False, readMode)
	# If there is no text, sleep because sometimes it takes a while for the new file to show up in the file system.
	if text == '':
		time.sleep(0.25)
		text = getFileText(fileName, False, readMode)
	if text == '':
		time.sleep(2.0)
		text = getFileText(fileName, printWarning, readMode)
	if text == '' and printWarning:
		print('The file %s does not exist.' % fileName)
	return base64.b64encode(text)

def getFileText(fileName, printWarning=True, readMode='r'):
	'Get the entire text of a file.'
	try:
		file = open(fileName, readMode)
		fileText = file.read()
		file.close()
		return fileText
	except IOError:
		if printWarning:
			print('The file %s does not exist.' % fileName)
	return ''

def getHomePath(fileName=''):
	'Get the home directory path.'
	homePath = os.path.abspath(os.path.expanduser('~'))
	if fileName == '':
		return homePath
	return os.path.join(homePath, fileName)

def getHomeSettingsPath(fileName=''):
	'Get the astravault directory path, which is the home directory joined with settings joined with astravault.'
	homeSettingsDirectory = os.path.join(getHomePath('settings'), 'astravault')
	if fileName == '':
		return homeSettingsDirectory
	return os.path.join(homeSettingsDirectory, fileName)

def getTextLines(text):
	'Get the all the lines of text of a text.'
	textLines = text.replace('\r', '\n').replace('\n\n', '\n').split('\n')
	if len(textLines) == 1:
		if textLines[0] == '':
			return []
	return textLines

def makeDirectory(directory):
	'Make a directory if it does not already exist.'
	if os.path.isdir(directory):
		return
	try:
		os.makedirs(directory)
		print('The following directory was made:')
		print(os.path.abspath(directory))
	except OSError:
		print('Astravault can not make the directory %s so give it read/write permission for that directory and the containing directory.' % directory)

def writeFileText(fileName, fileText, writeMode='w+'):
	'Write a text to a file.'
	try:
		file = open(fileName, writeMode)
		file.write(fileText)
		file.close()
	except IOError:
		print('The file ' + fileName + ' can not be written to.')


class Astravault:
	'A class to handle an Astravault.'
	def __init__(self):
		'Make empty Astravault.'
		self.attachmentName = 'galileo.astr'
		self.emailFrom = ''
		self.emailTo = ''
		self.mailServer = ''
		self.messageBody = 'Astronomy data from Galileo observatory.'
		self.password = ''
		self.port = 25
		self.subject = 'Astronomy Data'
		self.temporaryPassword = ''
		self.walletPath = os.path.join(getHomePath('.bitcoin'), 'wallet.dat')

	def __repr__(self):
		"Get the string representation of this Astravault."
		return self.toString().replace('\t', ' ')

	def decryptWallet(self):
		'Decrypt aes256 file and save is as wallet.dat.'
		print('Decrypt aes256 file and save as wallet.dat.')
		password = self.getConfirmedPassword()
		subprocess.Popen(['openssl', 'enc', '-d', '-aes256', '-in', self.attachmentName, '-out', 'wallet.dat', '-k', password])
		walletData = getFileText(self.walletPath, False, 'rb')
		if walletData == '':
			print('There is no wallet in the bitcoin directory, so the decrypted wallet will be moved there.')
			time.sleep(0.25)
			shutil.move('wallet.dat', self.walletPath)

	def encryptMailShred(self):
		'Encrypt bitcoin wallet, mail it, then shred it.'
		if not getFileText(self.walletPath):
			print('There is no wallet in the bitcoin directory, so decryption will be attempted.')
			self.decryptWallet()
			return True
		if not self.encryptWallet():
			return False
		if not self.mailWallet():
			return False
		walletData = getFileText(self.walletPath, False, 'rb')
		if walletData == '':
			print('Warning, encryptMailShred function could not read the wallet.')
			return False
		try:
			print('Now that wallet has been encrypted and mailed, the original will be shredded.')
			subprocess.Popen(['shred', '-u', self.walletPath])
		except:
			print('Warning, could not shred wallet.')

	def encryptWallet(self):
		'Encrypt bitcoin wallet.'
		if self.password == 'DoNotBotherEncryptingBecauseTheWalletIsAlreadyEncrypted.':
			print('Saving bitcoin wallet as %s.' % self.attachmentName)
			try:
				shutil.copy2(self.walletPath, self.attachmentName)
			except:
				print('Warning, attempt to save wallet failed.')
				return False
			return True
		print('Enter password to encrypt bitcoin wallet and save as %s.' % self.attachmentName)
		try:
			password = self.getConfirmedPassword()
			arguments = ['openssl', 'enc', '-aes256', '-in', self.walletPath, '-out', self.attachmentName, '-k', password]
			subprocess.Popen(arguments)
		except:
			print('Warning, attempt to encrypt wallet failed.')
			return False
		return True

	def getConfirmedPassword(self):
		'Get confirmed password, if it is not the same, keep asking.'
		if self.temporaryPassword != '':
			return self.temporaryPassword
		if self.password != '':
			return self.password
		while True:
			password = getpass.getpass()
			confirmPassword = getpass.getpass('Confirm password:')
			if password == confirmPassword:
				if len(password) > 7:
					print('Password is confirmed, openssl will be invoked.')
					return password
				else:
					print('Password is too short, password must have at least 8 characters.')
					print('When protecting money, a password should have at least 20 characters.')
			else:
				print('Passwords were different, so the password will be requested again.')

	def mailWallet(self):
		'Mail wallet from mail server.'
		encodedBinary = getEncodedBinary(self.attachmentName)
		mimeVersionString = 'MIME-Version: 1.0'
		uniqueMarker = '===========A_Unique_Marker'
		entireContent = encodedBinary + self.messageBody
		while uniqueMarker in entireContent:
			uniqueMarker += '='
		uniqueMarker += '==========='
		# Add header.
		messageLines = ['Content-Type: multipart/mixed; boundary="%s"' % uniqueMarker]
		messageLines.append(mimeVersionString)
		messageLines.append('From: %s' % self.emailFrom)
		messageLines.append('To: %s' % self.emailTo)
		# Date is in a try catch block in case formatdate does not work.
		try:
			from email.Utils import formatdate
			messageLines.append('Date: %s' % formatdate(localtime=True))
		except:
			pass
		messageLines.append('Subject: %s' % self.subject)
		messageLines.append('--%s' % uniqueMarker)
		# Add body.
		messageLines.append('Content-Type: text/plain; charset="us-ascii"')
		messageLines.append(mimeVersionString)
		messageLines.append('Content-Transfer-Encoding: 7bit\n')
		messageLines.append('%s' % self.messageBody)
		messageLines.append('--%s' % uniqueMarker)
		# Add attachment.
		messageLines.append('Content-Type: application/octet-stream')
		messageLines.append(mimeVersionString)
		messageLines.append('Content-Transfer-Encoding: base64')
		messageLines.append('Content-Disposition: attachment; filename="%s"\n' % self.attachmentName)
		messageLines.append('%s' % encodedBinary)
		messageLines.append('--%s--' % uniqueMarker)
		message = '\n'.join(messageLines)
		try:
			smtpObj = smtplib.SMTP(self.mailServer, int(self.port))
			smtpObj.sendmail(self.emailFrom, self.emailTo.split(','), message)
			smtpObj.close()
			print('')
			print('Mail has been sent from: %s to %s.' % (self.emailFrom, self.emailTo))
			print('The subject is: "%s"' % self.subject)
			if len(self.messageBody) > 60:
				print('The first twenty characters of the message body are: "%s.."' % self.messageBody[: 20])
			else:
				print('The message body is: "%s"' % self.messageBody)
			print('The attachment file name is: "%s"' % self.attachmentName)
			print('')
		except smtplib.SMTPException:
			print('Warning, attempt to send mail failed.')
			return False
		return True

	def parseArgument(self, argument):
		'Parse argument.'
		if argument == '-h':
			print(__doc__)
		elif argument == '-pr':
			print(self)

	def parseArgumentPair(self, argument, nextArgument):
		'Parse argument pair.'
		if argument == '-a':
			self.attachmentName = nextArgument
		elif argument == '-f':
			self.emailFrom = nextArgument
		elif argument == '-t':
			self.emailTo = nextArgument
		elif argument == '-ma':
			self.mailServer = nextArgument
		elif argument == '-me':
			self.messageBody = nextArgument
		elif argument == '-permanent':
			self.password = nextArgument
		elif argument == '-po':
			self.port = nextArgument
		elif argument == '-s':
			self.subject = nextArgument
		elif argument == '-te':
			self.temporaryPassword = nextArgument
			if len(self.temporaryPassword) < 8:
				print('Saved temporary password is too short (less than 8 characters), so a new password will be requested.')
				self.temporaryPassword = ''
		elif argument == '-w':
			self.walletPath = nextArgument

	def parseArguments(self, arguments):
		'Parse arguments.'
		for argumentIndex, argument in enumerate(arguments):
			if argument.startswith('-'):
				nextIndex = argumentIndex + 1
				nextArgument = ''
				if nextIndex < len(arguments):
					self.parseArgumentPair(argument, arguments[nextIndex])
				self.parseArgument(argument)
		if self.password != '' and len(self.password) < 8:
			print('Saved password is too short (less than 8 characters), so a new password will be requested.')
			self.password = ''

	def readSettings(self):
		'Read from settings directory.'
		astravaultPath = getHomeSettingsPath('astravault.csv')
		lines = getTextLines(getFileText(astravaultPath))
		for line in lines:
			firstWord = ''
			secondWord = ''
			words = line.split('\t')
			if len(words) > 1:
				firstWord = words[0].replace(':', '').replace(' ', '')
			if len(firstWord) > 0:
				firstWord = firstWord[0].lower() + firstWord[1 :]
				secondWord = words[1]
			if firstWord == 'attachmentName':
				self.attachmentName = secondWord
			elif firstWord == 'emailFrom':
				self.emailFrom = secondWord
			elif firstWord == 'emailTo':
				self.emailTo = secondWord
			elif firstWord == 'mailServer':
				self.mailServer = secondWord
			elif firstWord == 'messageBody':
				self.messageBody = secondWord
			elif firstWord == 'password':
				self.password = secondWord
			elif firstWord == 'port':
				self.port = secondWord
			elif firstWord == 'subject':
				self.subject = secondWord
			elif firstWord == 'walletPath':
				self.walletPath = secondWord

	def save(self):
		'Save to settings directory.'
		homeSettingsPath = getHomeSettingsPath()
		makeDirectory(homeSettingsPath)
		textLines = self.toString().split('\n')
		textLines.append('Password:\t%s' % self.password)
		textLines.sort()
		text = 'Format is tab separated settings.' + '\n'.join(textLines)
		writeFileText(os.path.join(homeSettingsPath, 'astravault.csv'), text)

	def toggle(self):
		'If there is a bitcoin wallet, encrypt the bitcoin wallet, mail it, then shred it; otherwise decrypt it.'
		if getFileText(self.walletPath, False, 'rb') == '':
			self.decryptWallet()
		else:
			self.encryptMailShred()

	def toString(self):
		'Get class variables as string.'
		cString = cStringIO.StringIO()
		cString.write('Attachment Name:\t%s\n' % self.attachmentName)
		cString.write('Email From:\t%s\n' % self.emailFrom)
		cString.write('Email To:\t%s\n' % self.emailTo)
		cString.write('Mail Server:\t%s\n' % self.mailServer)
		cString.write('Message Body:\t%s\n' % self.messageBody)
		cString.write('Port:\t%s\n' % self.port)
		cString.write('Subject:\t%s\n' % self.subject)
		cString.write('WalletPath:\t%s\n' % self.walletPath)
		return cString.getvalue()


def main():
	'Get Astravault and decrypt or encrypt and/or send mail.'
	arguments = sys.argv[1 :]
	astravault = Astravault()
	astravault.readSettings()
	astravault.parseArguments(arguments)
	astravault.save()
	if len(arguments) < 1 or '-em' in arguments:
		if astravault.encryptWallet():
			astravault.mailWallet()
		return
	if '-d' in arguments:
		astravault.decryptWallet()
		return
	if '-e' in arguments:
		astravault.encryptWallet()
		return
	if '-emshred' in arguments:
		astravault.encryptMailShred()
		return
	if '-m' in arguments:
		astravault.mailWallet()
	if '-toggle' in arguments:
		astravault.toggle()


if __name__ == '__main__':
	main()
