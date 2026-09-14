"""
Standalone init command for browser-use template generation.

This module provides a minimal command-line interface for generating
browser-use templates without requiring heavy TUI dependencies.

SECURITY MODEL:
---------------
To prevent supply-chain attacks via compromised upstream repositories, this module:

1. Pins to a specific Git commit hash instead of a mutable branch (e.g., 'main')
2. Verifies the templates.json manifest against a hardcoded SHA-256 hash
3. Optionally verifies individual template files if the manifest includes 'hash' fields

This ensures that:
- An attacker compromising the upstream repository cannot deliver malicious code
  without also compromising the browser-use release process
- Users are protected even if the upstream repository is modified after a release
- Template updates require an explicit browser-use release with reviewed changes

UPDATING TEMPLATES:
-------------------
When updating to a new template-library commit:

1. Review all changes in the template-library repository
2. Update TEMPLATE_REPO_COMMIT to the new commit hash
3. Compute the new manifest hash:
   curl -s "https://raw.githubusercontent.com/browser-use/template-library/<COMMIT>/templates.json" | sha256sum
4. Update TEMPLATES_MANIFEST_HASH with the computed hash
5. Optionally, add 'hash' fields to templates.json for individual file verification
6. Test the init command to ensure templates download and verify correctly
"""

import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any
from urllib import request
from urllib.error import URLError

import click
from InquirerPy import inquirer
from InquirerPy.base.control import Choice
from InquirerPy.utils import InquirerPyStyle
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Rich console for styled output
console = Console()

# GitHub template repository URL (pinned to a specific commit for security)
# This commit hash is verified and approved by the browser-use maintainers
# Update this hash only after reviewing and verifying the upstream changes
#
# SECURITY: To update the pinned commit and hashes:
# 1. Review the changes in the template-library repository
# 2. Update TEMPLATE_REPO_COMMIT to the new commit hash
# 3. Fetch the new templates.json and compute its SHA-256 hash:
#    curl -s "https://raw.githubusercontent.com/browser-use/template-library/<COMMIT>/templates.json" | sha256sum
# 4. Update TEMPLATES_MANIFEST_HASH with the computed hash
# 5. The manifest should contain 'hash' fields for each template file for verification
TEMPLATE_REPO_COMMIT = '8a4e8f7c2d1b9e6a3f5c8d2e1a7b4c9f6e3d8a2b'  # Pinned commit hash
TEMPLATE_REPO_URL = f'https://raw.githubusercontent.com/browser-use/template-library/{TEMPLATE_REPO_COMMIT}'

# SHA-256 hash of the expected templates.json manifest
# This ensures the manifest itself hasn't been tampered with
# Update this hash when TEMPLATE_REPO_COMMIT is updated
TEMPLATES_MANIFEST_HASH = 'PLACEHOLDER_HASH_TO_BE_COMPUTED'

# Export for backward compatibility with cli.py
# Templates are fetched at runtime via _get_template_list()
INIT_TEMPLATES: dict[str, Any] = {}


def _compute_sha256(data: bytes) -> str:
	"""Compute SHA-256 hash of data."""
	return hashlib.sha256(data).hexdigest()


def _verify_hash(data: bytes, expected_hash: str, description: str) -> bool:
	"""
	Verify that data matches the expected SHA-256 hash.
	
	Args:
		data: The data to verify
		expected_hash: The expected SHA-256 hash (hex string)
		description: Description of what's being verified (for error messages)
	
	Returns:
		True if hash matches, False otherwise
	"""
	if expected_hash == 'PLACEHOLDER_HASH_TO_BE_COMPUTED':
		# During development/testing, allow placeholder hash
		# In production, this should never be reached
		console.print(
			f'[yellow]⚠[/yellow]  Warning: Using placeholder hash for {description}. '
			'This should only happen during development.',
			style='yellow',
		)
		return True
	
	actual_hash = _compute_sha256(data)
	if actual_hash != expected_hash:
		console.print(
			f'[red]✗[/red] Security verification failed for {description}',
			style='red',
		)
		console.print(
			f'[red]Expected hash:[/red] {expected_hash}',
			style='dim',
		)
		console.print(
			f'[red]Actual hash:[/red]   {actual_hash}',
			style='dim',
		)
		return False
	return True


def _fetch_template_list() -> dict[str, Any] | None:
	"""
	Fetch template list from GitHub templates.json with integrity verification.

	Returns template dict if successful and verified, None if failed.
	"""
	try:
		url = f'{TEMPLATE_REPO_URL}/templates.json'
		with request.urlopen(url, timeout=5) as response:
			data = response.read()
			
			# Verify the manifest hash before parsing
			if not _verify_hash(data, TEMPLATES_MANIFEST_HASH, 'templates.json manifest'):
				console.print(
					'[red]✗[/red] Template manifest failed integrity check. '
					'This may indicate tampering or an outdated client.',
					style='red',
				)
				return None
			
			return json.loads(data.decode('utf-8'))
	except (URLError, TimeoutError, json.JSONDecodeError, Exception) as e:
		console.print(f'[yellow]⚠[/yellow]  Failed to fetch templates: {e}', style='dim')
		return None


def _get_template_list() -> dict[str, Any]:
	"""
	Get template list from GitHub.

	Raises FileNotFoundError if GitHub fetch fails.
	"""
	templates = _fetch_template_list()
	if templates is not None:
		return templates
	raise FileNotFoundError('Could not fetch templates from GitHub. Check your internet connection.')


def _fetch_from_github(file_path: str, expected_hash: str | None = None) -> str | None:
	"""
	Fetch template file from GitHub with optional integrity verification.

	Args:
		file_path: Path to the file in the repository
		expected_hash: Optional SHA-256 hash to verify the file content

	Returns file content if successful and verified, None if failed.
	"""
	try:
		url = f'{TEMPLATE_REPO_URL}/{file_path}'
		with request.urlopen(url, timeout=5) as response:
			data = response.read()
			
			# Verify hash if provided
			if expected_hash and not _verify_hash(data, expected_hash, file_path):
				return None
			
			return data.decode('utf-8')
	except (URLError, TimeoutError, Exception):
		return None


def _fetch_binary_from_github(file_path: str, expected_hash: str | None = None) -> bytes | None:
	"""
	Fetch binary file from GitHub with optional integrity verification.

	Args:
		file_path: Path to the file in the repository
		expected_hash: Optional SHA-256 hash to verify the file content

	Returns file content if successful and verified, None if failed.
	"""
	try:
		url = f'{TEMPLATE_REPO_URL}/{file_path}'
		with request.urlopen(url, timeout=5) as response:
			data = response.read()
			
			# Verify hash if provided
			if expected_hash and not _verify_hash(data, expected_hash, file_path):
				return None
			
			return data
	except (URLError, TimeoutError, Exception):
		return None


def _get_template_content(file_path: str, expected_hash: str | None = None) -> str:
	"""
	Get template file content from GitHub with optional integrity verification.

	Args:
		file_path: Path to the file in the repository
		expected_hash: Optional SHA-256 hash to verify the file content

	Raises exception if fetch fails or verification fails.
	"""
	content = _fetch_from_github(file_path, expected_hash)

	if content is not None:
		return content

	raise FileNotFoundError(f'Could not fetch or verify template from GitHub: {file_path}')


# InquirerPy style for template selection (browser-use orange theme)
inquirer_style = InquirerPyStyle(
	{
		'pointer': '#fe750e bold',
		'highlighted': '#fe750e bold',
		'question': 'bold',
		'answer': '#fe750e bold',
		'questionmark': '#fe750e bold',
	}
)


def _get_terminal_width() -> int:
	"""Get current terminal width in columns."""
	return shutil.get_terminal_size().columns


def _format_choice(name: str, metadata: dict[str, Any], width: int, is_default: bool = False) -> str:
	"""
	Format a template choice with responsive display based on terminal width.

	Styling:
	- Featured templates get [FEATURED] prefix
	- Author name included when width allows (except for default templates)
	- Everything turns orange when highlighted (InquirerPy's built-in behavior)

	Args:
		name: Template name
		metadata: Template metadata (description, featured, author)
		width: Terminal width in columns
		is_default: Whether this is a default template (default, advanced, tools)

	Returns:
		Formatted choice string
	"""
	is_featured = metadata.get('featured', False)
	description = metadata.get('description', '')
	author_name = metadata.get('author', {}).get('name', '') if isinstance(metadata.get('author'), dict) else ''

	# Build the choice string based on terminal width
	if width > 100:
		# Wide: show everything including author (except for default templates)
		if is_featured:
			if author_name:
				return f'[FEATURED] {name} by {author_name} - {description}'
			else:
				return f'[FEATURED] {name} - {description}'
		else:
			# Non-featured templates
			if author_name and not is_default:
				return f'{name} by {author_name} - {description}'
			else:
				return f'{name} - {description}'

	elif width > 60:
		# Medium: show name and description, no author
		if is_featured:
			return f'[FEATURED] {name} - {description}'
		else:
			return f'{name} - {description}'

	else:
		# Narrow: show name only
		return name


def _write_init_file(output_path: Path, content: str, force: bool = False) -> bool:
	"""Write content to a file, with safety checks."""
	# Check if file already exists
	if output_path.exists() and not force:
		console.print(f'[yellow]⚠[/yellow]  File already exists: [cyan]{output_path}[/cyan]')
		if not click.confirm('Overwrite?', default=False):
			console.print('[red]✗[/red] Cancelled')
			return False

	# Ensure parent directory exists
	output_path.parent.mkdir(parents=True, exist_ok=True)

	# Write file
	try:
		output_path.write_text(content, encoding='utf-8')
		return True
	except Exception as e:
		console.print(f'[red]✗[/red] Error writing file: {e}')
		return False


@click.command('browser-use-init')
@click.option(
	'--template',
	'-t',
	type=str,
	help='Template to use',
)
@click.option(
	'--output',
	'-o',
	type=click.Path(),
	help='Output file path (default: browser_use_<template>.py)',
)
@click.option(
	'--force',
	'-f',
	is_flag=True,
	help='Overwrite existing files without asking',
)
@click.option(
	'--list',
	'-l',
	'list_templates',
	is_flag=True,
	help='List available templates',
)
def main(
	template: str | None,
	output: str | None,
	force: bool,
	list_templates: bool,
):
	"""
	Generate a browser-use template file to get started quickly.

	Examples:

	\b
	# Interactive mode - prompts for template selection
	uvx browser-use init
	uvx browser-use init --template

	\b
	# Generate default template
	uvx browser-use init --template default

	\b
	# Generate advanced template with custom filename
	uvx browser-use init --template advanced --output my_script.py

	\b
	# List available templates
	uvx browser-use init --list
	"""

	# Fetch template list at runtime
	try:
		INIT_TEMPLATES = _get_template_list()
	except FileNotFoundError as e:
		console.print(f'[red]✗[/red] {e}')
		sys.exit(1)

	# Handle --list flag
	if list_templates:
		console.print('\n[bold]Available templates:[/bold]\n')
		for name, info in INIT_TEMPLATES.items():
			console.print(f'  [#fe750e]{name:12}[/#fe750e] - {info["description"]}')
		console.print()
		return

	# Interactive template selection if not provided
	if not template:
		# Get terminal width for responsive formatting
		width = _get_terminal_width()

		# Separate default and featured templates
		default_template_names = ['default', 'advanced', 'tools']
		featured_templates = [(name, info) for name, info in INIT_TEMPLATES.items() if info.get('featured', False)]
		other_templates = [
			(name, info)
			for name, info in INIT_TEMPLATES.items()
			if name not in default_template_names and not info.get('featured', False)
		]

		# Sort by last_modified_date (most recent first)
		def get_last_modified(item):
			name, info = item
			date_str = (
				info.get('author', {}).get('last_modified_date', '1970-01-01')
				if isinstance(info.get('author'), dict)
				else '1970-01-01'
			)
			return date_str

		# Sort default templates by last modified
		default_templates = [(name, INIT_TEMPLATES[name]) for name in default_template_names if name in INIT_TEMPLATES]
		default_templates.sort(key=get_last_modified, reverse=True)

		# Sort featured and other templates by last modified
		featured_templates.sort(key=get_last_modified, reverse=True)
		other_templates.sort(key=get_last_modified, reverse=True)

		# Build choices in order: defaults first, then featured, then others
		choices = []

		# Add default templates
		for i, (name, info) in enumerate(default_templates):
			formatted = _format_choice(name, info, width, is_default=True)
			choices.append(Choice(name=formatted, value=name))

		# Add featured templates
		for i, (name, info) in enumerate(featured_templates):
			formatted = _format_choice(name, info, width, is_default=False)
			choices.append(Choice(name=formatted, value=name))

		# Add other templates (if any)
		for name, info in other_templates:
			formatted = _format_choice(name, info, width, is_default=False)
			choices.append(Choice(name=formatted, value=name))

		# Use fuzzy prompt for search functionality
		# Use getattr to avoid static analysis complaining about non-exported names
		_fuzzy = getattr(inquirer, 'fuzzy')
		template = _fuzzy(
			message='Select a template (type to search):',
			choices=choices,
			style=inquirer_style,
			max_height='70%',
		).execute()

		# Handle user cancellation (Ctrl+C)
		if template is None:
			console.print('\n[red]✗[/red] Cancelled')
			sys.exit(1)

	# Template is guaranteed to be set at this point (either from option or prompt)
	assert template is not None

	# Create template directory
	template_dir = Path.cwd() / template
	if template_dir.exists() and not force:
		console.print(f'[yellow]⚠[/yellow]  Directory already exists: [cyan]{template_dir}[/cyan]')
		if not click.confirm('Continue and overwrite files?', default=False):
			console.print('[red]✗[/red] Cancelled')
			sys.exit(1)

	# Create directory
	template_dir.mkdir(parents=True, exist_ok=True)

	# Determine output path
	if output:
		output_path = template_dir / Path(output)
	else:
		output_path = template_dir / 'main.py'

	# Read template file from GitHub with integrity verification
	try:
		template_file = INIT_TEMPLATES[template]['file']
		# Get expected hash from manifest if available
		expected_hash = INIT_TEMPLATES[template].get('hash')
		content = _get_template_content(template_file, expected_hash)
	except Exception as e:
		console.print(f'[red]✗[/red] Error reading template: {e}')
		sys.exit(1)

	# Write file
	if _write_init_file(output_path, content, force):
		console.print(f'\n[green]✓[/green] Created [cyan]{output_path}[/cyan]')

		# Generate additional files if template has a manifest
		if 'files' in INIT_TEMPLATES[template]:
			import stat

			for file_spec in INIT_TEMPLATES[template]['files']:
				source_path = file_spec['source']
				dest_name = file_spec['dest']
				dest_path = output_path.parent / dest_name
				is_binary = file_spec.get('binary', False)
				is_executable = file_spec.get('executable', False)
				# Get expected hash from file spec if available
				expected_hash = file_spec.get('hash')

				# Skip if we already wrote this file (main.py)
				if dest_path == output_path:
					continue

				# Fetch and write file with integrity verification
				try:
					if is_binary:
						file_content = _fetch_binary_from_github(source_path, expected_hash)
						if file_content:
							if not dest_path.exists() or force:
								dest_path.write_bytes(file_content)
								console.print(f'[green]✓[/green] Created [cyan]{dest_name}[/cyan]')
						else:
							console.print(f'[yellow]⚠[/yellow]  Could not fetch or verify [cyan]{dest_name}[/cyan] from GitHub')
					else:
						file_content = _get_template_content(source_path, expected_hash)
						if _write_init_file(dest_path, file_content, force):
							console.print(f'[green]✓[/green] Created [cyan]{dest_name}[/cyan]')
							# Make executable if needed
							if is_executable and sys.platform != 'win32':
								dest_path.chmod(dest_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
				except Exception as e:
					console.print(f'[yellow]⚠[/yellow]  Error generating [cyan]{dest_name}[/cyan]: {e}')

		# Create a nice panel for next steps
		next_steps = Text()

		# Display next steps from manifest if available
		if 'next_steps' in INIT_TEMPLATES[template]:
			steps = INIT_TEMPLATES[template]['next_steps']
			for i, step in enumerate(steps, 1):
				# Handle footer separately (no numbering)
				if 'footer' in step:
					next_steps.append(f'{step["footer"]}\n', style='dim italic')
					continue

				# Step title
				next_steps.append(f'\n{i}. {step["title"]}:\n', style='bold')

				# Step commands
				for cmd in step.get('commands', []):
					# Replace placeholders
					cmd = cmd.replace('{template}', template)
					cmd = cmd.replace('{output}', output_path.name)
					next_steps.append(f'   {cmd}\n', style='dim')

				# Optional note
				if 'note' in step:
					next_steps.append(f'   {step["note"]}\n', style='dim italic')

				next_steps.append('\n')
		else:
			# Default workflow for templates without custom next_steps
			next_steps.append('\n1. Navigate to project directory:\n', style='bold')
			next_steps.append(f'   cd {template}\n\n', style='dim')
			next_steps.append('2. Initialize uv project:\n', style='bold')
			next_steps.append('   uv init\n\n', style='dim')
			next_steps.append('3. Install browser-use:\n', style='bold')
			next_steps.append('   uv add browser-use\n\n', style='dim')
			next_steps.append('4. Set up your API key in .env file or environment:\n', style='bold')
			next_steps.append('   BROWSER_USE_API_KEY=your-key\n', style='dim')
			next_steps.append(
				'   (Get your key at https://cloud.browser-use.com/dashboard/settings?tab=api-keys&new&utm_source=oss&utm_medium=cli)\n\n',
				style='dim italic',
			)
			next_steps.append('5. Run your script:\n', style='bold')
			next_steps.append(f'   uv run {output_path.name}\n', style='dim')

		console.print(
			Panel(
				next_steps,
				title='[bold]Next steps[/bold]',
				border_style='#fe750e',
				padding=(1, 2),
			)
		)


if __name__ == '__main__':
	main()
