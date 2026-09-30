"""Synthetic archive/ELF metadata tests. Never execute an Ubuntu image."""
from contextlib import contextmanager
from io import BytesIO, StringIO
import hashlib
import json
import lzma
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from siem.rbac import inspect_systemd_elf as elf
from siem.rbac import verify_systemd_runtime_archive as m
from test_pid1_ubuntu_archive import ar_member, bsdtar_path, release

BASE, DYNAMIC, STRINGS = 0x400000, 512, 8192


def image(needed=('libc.so.6',), *, soname=None, interpreter=None,
          rpath=None, runpath=None, extra=(), terminal_value=0, tail=b''):
    table = bytearray(b'\0')

    def text(value):
        start = len(table)
        table.extend(value.encode() + b'\0')
        return start

    pairs = [(1, text(name)) for name in needed]
    for tag, value in ((14, soname), (15, rpath), (29, runpath)):
        if value is not None:
            pairs.append((tag, text(value)))
    pairs += [(5, BASE + STRINGS), (10, len(table)), *extra, (0, terminal_value)]
    dynamic = b''.join(struct.pack('<qQ', t, v) for t, v in pairs) + tail
    raw = bytearray(16 * 1024)
    headers = [(1, 5, 0, BASE, BASE, len(raw), len(raw), 4096),
               (2, 6, DYNAMIC, BASE + DYNAMIC, BASE + DYNAMIC,
                len(dynamic), len(dynamic), 8)]
    if interpreter is not None:
        value = interpreter.encode() + b'\0'
        raw[384:384 + len(value)] = value
        headers.append((3, 4, 384, BASE + 384, BASE + 384, len(value), len(value), 1))
    raw[:64] = struct.pack('<16sHHIQQQIHHHHHH', b'\x7fELF\x02\x01\x01' + b'\0' * 9,
                          3, 62, 1, 0, 64, 0, 0, 64, 56, len(headers), 0, 0, 0)
    for i, h in enumerate(headers):
        struct.pack_into('<IIQQQQQQ', raw, 64 + i * 56, *h)
    raw[DYNAMIC:DYNAMIC + len(dynamic)] = dynamic
    raw[STRINGS:STRINGS + len(table)] = table
    return bytes(raw)


def edit(raw, fmt, offset, value):
    out = bytearray(raw)
    struct.pack_into(fmt, out, offset, value)
    return bytes(out)


def images():
    return {'manager': image(('libsystemd-core-259.so', 'libsystemd-shared-259.so', 'libc.so.6'),
                             interpreter='/lib64/ld-linux-x86-64.so.2',
                             runpath='/usr/lib/x86_64-linux-gnu/systemd'),
            'core': image(('libsystemd-shared-259.so', 'libc.so.6'), soname='libsystemd-core-259.so'),
            'shared': image(('libc.so.6',), soname='libsystemd-shared-259.so')}


def deb(package, values):
    stream = BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        for role, owner, member in m.OBJECTS:
            if owner != package:
                continue
            item = tarfile.TarInfo('./' + member)
            item.size = len(values[role])
            archive.addfile(item, BytesIO(values[role]))
    return b'!<arch>\n' + ar_member('debian-binary', b'2.0\n') + ar_member('data.tar.gz', stream.getvalue())


def stanza(package, filename, raw):
    return (f'Package: {package}\nVersion: {m.VERSION}\nArchitecture: amd64\n'
            f'Source: systemd\nFilename: pool/main/s/systemd/{filename}\n'
            f'Size: {len(raw)}\nSHA256: {hashlib.sha256(raw).hexdigest()}\n\n').encode()


class ElfMetadataTests(unittest.TestCase):
    def stop(self, code, raw):
        with self.assertRaisesRegex(m.archive.Stop, '^' + code + '$'):
            elf.inspect_elf64(raw)

    def test_exact_manager_and_library_metadata_without_sections(self):
        values = images()
        result = elf.inspect_elf64(values['manager'])
        self.assertEqual(result, {'elf_type': 'ET_DYN', 'interpreter': '/lib64/ld-linux-x86-64.so.2',
                                 'needed': ['libsystemd-core-259.so', 'libsystemd-shared-259.so',
                                            'libc.so.6'], 'soname': None, 'rpath': None,
                                 'runpath': '/usr/lib/x86_64-linux-gnu/systemd'})
        self.assertEqual(elf.inspect_elf64(values['core'])['soname'], 'libsystemd-core-259.so')
        self.assertIsNone(elf.inspect_elf64(values['core'])['interpreter'])

    def test_input_types_and_total_size_bounded(self):
        for raw in (None, bytearray(image()), b'', b'x' * 63):
            self.stop('ELF_SIZE', raw)
        with patch.object(elf, 'MAX_IMAGE', 100):
            self.stop('ELF_SIZE', image())

    def test_class_endianness_machine_version_and_header_sizes(self):
        raw = image()
        for fmt, offset, value in (('B', 0, 0), ('B', 4, 1), ('B', 5, 2),
                                   ('B', 6, 0), ('B', 7, 9), ('B', 8, 1),
                                   ('H', 16, 1), ('H', 18, 183), ('I', 20, 2),
                                   ('H', 52, 63), ('H', 54, 55), ('H', 56, 0),
                                   ('H', 56, 257), ('Q', 32, 63)):
            self.stop('ELF_HEADER', edit(raw, fmt, offset, value))
        self.assertEqual(elf.inspect_elf64(edit(raw, 'H', 16, 2))['elf_type'], 'ET_EXEC')

    def test_program_header_and_segment_file_bounds(self):
        raw = image()
        self.stop('ELF_BOUNDS', edit(raw, 'Q', 32, len(raw) - 1))
        self.stop('ELF_BOUNDS', edit(raw, 'Q', 64 + 8, len(raw) + 1))
        self.stop('ELF_BOUNDS', edit(raw, 'Q', 64 + 32, len(raw) + 1))

    def test_segment_memory_alignment_and_address_overflow(self):
        raw = image()
        for offset, value in ((64 + 40, 1), (64 + 48, 3), (64 + 16, (1 << 64) - 1)):
            self.stop('ELF_SEGMENT', edit(raw, 'Q', offset, value))

    def test_required_load_dynamic_and_unique_interpreter(self):
        raw = image()
        self.stop('ELF_SEGMENTS', edit(raw, 'I', 64, 0))
        self.stop('ELF_SEGMENTS', edit(raw, 'I', 120, 0))
        self.stop('ELF_SEGMENTS', edit(raw, 'I', 64, 2))
        out = bytearray(image(interpreter='/a'))
        out[232:288] = out[176:232]
        struct.pack_into('<H', out, 56, 4)
        self.stop('ELF_SEGMENTS', bytes(out))

    def test_dynamic_segment_mapping_and_bounded_entry_count(self):
        raw = image()
        self.stop('ELF_MAPPING', edit(raw, 'Q', 120 + 16, BASE + 900))
        self.stop('ELF_DYNAMIC', edit(raw, 'Q', 120 + 32, 47))
        with patch.object(elf, 'MAX_DYNAMIC', 1):
            self.stop('ELF_DYNAMIC', raw)
        out = bytearray(raw)
        out[176:232] = out[64:120]
        struct.pack_into('<H', out, 56, 3)
        self.stop('ELF_MAPPING', bytes(out))

    def test_missing_dynamic_terminator_refused(self):
        raw = image()
        self.stop('ELF_DYNAMIC', edit(raw, 'q', DYNAMIC + 3 * 16, 123))

    def test_dt_null_value_and_after_terminator_bytes_are_not_entries(self):
        for value in (0, 53140, (1 << 64) - 1):
            result = elf.inspect_elf64(image(terminal_value=value,
                                            tail=struct.pack('<qQ', 5, 999999999)))
            self.assertEqual(result['needed'], ['libc.so.6'])

    def test_missing_and_duplicate_critical_tags_refused(self):
        raw = image()
        self.stop('ELF_TAG', edit(raw, 'q', DYNAMIC + 16, 123))
        self.stop('ELF_TAG', image(extra=((5, BASE + STRINGS),)))
        for tag in (10, 14, 15, 29):
            value = image(soname='one.so', rpath='/a', runpath='/b', extra=((tag, 1),))
            self.stop('ELF_TAG', value)

    def test_string_table_size_mapping_and_initial_null(self):
        raw = image()
        self.stop('ELF_STRTAB', edit(raw, 'Q', DYNAMIC + 2 * 16 + 8, 0))
        self.stop('ELF_STRTAB', edit(raw, 'Q', DYNAMIC + 2 * 16 + 8, elf.MAX_STRTAB + 1))
        self.stop('ELF_MAPPING', edit(raw, 'Q', DYNAMIC + 16 + 8, BASE + len(raw)))
        self.stop('ELF_STRTAB', edit(raw, 'B', STRINGS, 1))

    def test_string_offsets_termination_tokens_and_duplicate_needed(self):
        raw = image()
        self.stop('ELF_STRING', edit(raw, 'Q', DYNAMIC + 8, 999999))
        self.stop('ELF_STRING', edit(raw, 'Q', DYNAMIC + 8, 0))
        self.stop('ELF_STRING', image(('a/b.so',)))
        self.stop('ELF_STRING', image(('a\n.so',)))
        self.stop('ELF_NEEDED', image(('one.so', 'one.so')))
        raw = edit(raw, 'B', STRINGS + len(b'\0libc.so.6'), 65)
        self.stop('ELF_STRING', raw)

    def test_needed_count_and_string_length_limits(self):
        self.stop('ELF_NEEDED', image(tuple('l%02d.so' % i for i in range(65))))
        self.stop('ELF_STRING', image(('x' * 256,)))
        self.stop('ELF_STRING', image(runpath='/' + 'x' * 4096))

    def test_interpreter_size_embedded_null_and_path_grammar(self):
        raw = image(interpreter='/a')
        self.stop('ELF_INTERPRETER', edit(raw, 'Q', 176 + 32, 1))
        self.stop('ELF_INTERPRETER', edit(raw, 'B', 384 + 2, 65))
        self.stop('ELF_INTERPRETER', image(interpreter='relative'))
        self.stop('ELF_INTERPRETER', image(interpreter='/a\0/b'))

    def test_rpath_runpath_are_observed_not_resolved(self):
        result = elf.inspect_elf64(image(rpath='$ORIGIN:/other', runpath='/fixed'))
        self.assertEqual(result['rpath'], '$ORIGIN:/other')
        self.assertEqual(result['runpath'], '/fixed')
        self.stop('ELF_STRING', image(runpath='/a b'))

    def test_reader_has_no_io_or_loader_calls(self):
        raw = image()
        with patch('builtins.open') as opened, patch('subprocess.run') as run, \
                patch('ctypes.CDLL') as loaded:
            elf.inspect_elf64(raw)
            opened.assert_not_called()
            run.assert_not_called()
            loaded.assert_not_called()


class RuntimeArchiveTests(unittest.TestCase):
    def stop(self, code, call):
        with self.assertRaisesRegex(m.archive.Stop, '^' + code + '$'):
            call()

    @contextmanager
    def bundle(self):
        values = images()
        contents = {filename: deb(package, values) for package, filename in m.PACKAGES}
        plain = b''.join(stanza(package, filename, contents[filename])
                         for package, filename in m.PACKAGES)
        contents.update({'InRelease': b'signed-fixture', 'Packages.xz': lzma.compress(plain),
                         'ubuntu-archive-keyring.gpg': b'public-keyring-fixture'})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name, raw in contents.items():
                (root / name).write_bytes(raw)
            with patch.object(m.archive, '_verified_release', return_value=release(contents['Packages.xz'])):
                yield root, values, contents, plain

    def verify(self, root, values, **overrides):
        with patch.object(m, 'extracted_objects', return_value=values):
            return m.verify_runtime_bundle(root, Path('/fixture/gpgv'), Path('/fixture/bsdtar'),
                overrides.get('sha', hashlib.sha256(values['manager']).hexdigest()),
                overrides.get('size', len(values['manager'])))

    def test_exact_packages_members_literals_and_no_discovery_policy(self):
        self.assertEqual(m.VERSION, '259.5-0ubuntu3.4')
        self.assertEqual(m.PACKAGES, (('systemd', 'systemd_259.5-0ubuntu3.4_amd64.deb'),
                                     ('libsystemd-shared', 'libsystemd-shared_259.5-0ubuntu3.4_amd64.deb')))
        self.assertEqual(len(m.OBJECTS), 3)
        self.assertEqual(len(m.LITERALS), 10)
        self.assertEqual(m.OBJECTS[1][2], 'usr/lib/x86_64-linux-gnu/systemd/libsystemd-core-259.so')

    def test_two_exact_records_and_same_source_version(self):
        with self.bundle() as (_, _, contents, plain):
            records = m.package_records(contents['Packages.xz'])
            self.assertEqual([r['package'] for r in records], ['systemd', 'libsystemd-shared'])
            self.assertEqual([r['bytes'] for r in records],
                             [len(contents[f]) for _, f in m.PACKAGES])
            self.assertEqual(m.package_records(lzma.compress(plain.replace(
                b'Source: systemd', b'Source: systemd (' + m.VERSION.encode() + b')'))), records)

    def test_missing_duplicate_wrong_arch_version_and_filename_refused(self):
        with self.bundle() as (_, _, _, plain):
            for changed in (plain + plain, plain.split(b'\n\n')[0] + b'\n\n',
                            plain.replace(b'Architecture: amd64', b'Architecture: arm64'),
                            plain.replace(m.VERSION.encode(), b'259.5-other'),
                            plain.replace(b'pool/main/s/systemd/', b'pool/other/')):
                self.stop('RUNTIME_INDEX_PACKAGE', lambda: m.package_records(lzma.compress(changed)))

    def test_source_fold_digest_and_size_shapes_refused(self):
        with self.bundle() as (_, _, _, plain):
            for changed in (plain.replace(b'Source: systemd', b'Source: different'),
                            plain.replace(b'Source: systemd', b'Source: systemd\n continuation'),
                            plain.replace(b'SHA256: ', b'SHA256: X'),
                            plain.replace(b'Size: ', b'Size: 000000000000000000'),
                            plain.replace(b'Size: ', b'Size: x')):
                self.stop('RUNTIME_INDEX_PACKAGE', lambda: m.package_records(lzma.compress(changed)))

    def test_combined_chain_candidate_result_and_all_false_authority_flags(self):
        with self.bundle() as (root, values, _, _):
            result = self.verify(root, values)
            self.assertEqual([r['role'] for r in result['objects']], ['manager', 'core', 'shared'])
            self.assertEqual(len(result['literal_observations']), 10)
            self.assertEqual(result['objects'][0]['sha256'], hashlib.sha256(values['manager']).hexdigest())
            self.assertEqual(result['schema'], 1)
            for name, value in result.items():
                if type(value) is bool:
                    self.assertEqual(value, name in ('candidate_image_bytes_match', 'review_required'), name)

    def test_signature_and_index_checks_precede_extraction(self):
        with self.bundle() as (root, values, contents, _), patch.object(m, 'extracted_objects') as extract:
            with patch.object(m.archive, '_verified_release', side_effect=m.archive.Stop('ARCHIVE_SIGNER')):
                self.stop('ARCHIVE_SIGNER', lambda: self.verify(root, values))
            (root / 'Packages.xz').write_bytes(contents['Packages.xz'] + b'x')
            self.stop('INDEX_HASH', lambda: m.verify_runtime_bundle(root, Path('/gpgv'), Path('/tar'),
                      hashlib.sha256(values['manager']).hexdigest(), len(values['manager'])))
            extract.assert_not_called()

    def test_each_package_hash_checked_before_any_extraction(self):
        for _, filename in m.PACKAGES:
            with self.bundle() as (root, values, contents, _), patch.object(m, 'extracted_objects') as extract:
                raw = contents[filename]
                (root / filename).write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
                self.stop('RUNTIME_DEB_HASH', lambda: m.verify_runtime_bundle(
                    root, Path('/gpgv'), Path('/tar'), hashlib.sha256(values['manager']).hexdigest(),
                    len(values['manager'])))
                extract.assert_not_called()

    def test_candidate_digest_size_types_and_matching(self):
        with self.bundle() as (root, values, _, _):
            for sha in (None, 'bad', 'A' * 64):
                self.stop('CANDIDATE_DIGEST', lambda: self.verify(root, values, sha=sha))
            for size in (True, 0, -1, m.archive.MAX_IMAGE + 1):
                self.stop('CANDIDATE_SIZE', lambda: self.verify(root, values, size=size))
            self.stop('IMAGE_MISMATCH', lambda: self.verify(root, values, sha='f' * 64))
            self.stop('IMAGE_SIZE_MISMATCH', lambda: self.verify(root, values, size=len(values['manager']) + 1))

    def test_manager_interpreter_needed_and_library_soname_shapes(self):
        with self.bundle() as (root, values, _, _):
            for role, raw, code in (
                ('manager', image(), 'RUNTIME_MANAGER_SHAPE'),
                ('core', image(soname='wrong.so'), 'RUNTIME_LIBRARY_SHAPE'),
                ('shared', image(soname='libsystemd-shared-259.so', interpreter='/other'),
                 'RUNTIME_LIBRARY_SHAPE')):
                self.stop(code, lambda: self.verify(root, {**values, role: raw}))
            self.stop('RUNTIME_ELF_TYPE', lambda: self.verify(root,
                {**values, 'core': edit(values['core'], 'H', 16, 2)}))

    def test_literal_suffixes_not_semantic_or_live_path_proof(self):
        with self.bundle() as (root, values, _, _):
            raw = values['shared'] + b'prefix' + m.LITERALS[0].encode() + b'\0'
            result = self.verify(root, {**values, 'shared': raw})
            self.assertEqual(result['literal_observations'][0]['nul_terminated_suffix_counts']['shared'], 1)
            self.assertFalse(result['compiled_vendor_path_semantics_proven'])
            self.assertFalse(result['path_override_state_proven'])
            self.assertFalse(result['loaded_runtime_proven'])

    def test_stdout_extraction_uses_only_three_exact_members_without_shell(self):
        values = images()
        contents = {filename: deb(package, values) for package, filename in m.PACKAGES}
        calls = []

        def command(tool, args, **kw):
            calls.append(args)
            if args == ['-tf', '-']:
                members = (m.OBJECTS[:1] if len(calls) == 1 else m.OBJECTS[1:])
                stdout = b''.join(('./' + r[2] + '\r\n').encode() for r in members)
            else:
                role = next(r[0] for r in m.OBJECTS if args[-1] == './' + r[2])
                stdout = values[role]
            return type('Result', (), {'stdout': stdout})()

        with patch.object(m.archive, '_command', side_effect=command):
            self.assertEqual(m.extracted_objects(Path('/bsdtar'), contents), values)
        self.assertEqual(calls, [['-tf', '-'], ['-xOf', '-', './' + m.OBJECTS[0][2]],
                                ['-tf', '-'], ['-xOf', '-', './' + m.OBJECTS[1][2]],
                                ['-xOf', '-', './' + m.OBJECTS[2][2]]])

    def test_extraction_missing_duplicate_and_invalid_listing_refused(self):
        values = images()
        contents = {filename: deb(package, values) for package, filename in m.PACKAGES}
        for listing, code in ((b'', 'RUNTIME_TAR_MEMBER'),
                              (('./' + m.OBJECTS[0][2] + '\n').encode() * 2, 'RUNTIME_TAR_MEMBER'),
                              (b'bad\0', 'RUNTIME_TAR_LIST'), (b'bad\r', 'RUNTIME_TAR_LIST')):
            with patch.object(m.archive, '_command') as command:
                command.return_value.stdout = listing
                self.stop(code, lambda: m.extracted_objects(Path('/bsdtar'), contents))

    def test_real_bsdtar_extracts_both_synthetic_packages_when_available(self):
        tool = bsdtar_path()
        if tool is None:
            self.skipTest('bsdtar unavailable; never substitute GNU tar')
        values = images()
        contents = {filename: deb(package, values) for package, filename in m.PACKAGES}
        self.assertEqual(m.extracted_objects(tool, contents), values)

    def test_cli_root_refusal_before_reads_and_fixed_error_no_raw_details(self):
        args = ['--bundle', '/unused', '--gpgv', '/gpgv', '--bsdtar', '/tar',
                '--candidate-sha256', 'a' * 64, '--candidate-bytes', '10']
        with patch.object(m.os, 'geteuid', return_value=0, create=True), \
                patch.object(m, 'verify_runtime_bundle') as verify, patch('sys.stderr', new_callable=StringIO) as err:
            self.assertEqual(m.main(args), 1)
            self.assertEqual(err.getvalue(), 'STOP: ROOT_FORBIDDEN\n')
            verify.assert_not_called()
        with patch.object(m.os, 'geteuid', return_value=1000, create=True), \
                patch.object(m, 'verify_runtime_bundle', side_effect=OSError('PRIVATE')), \
                patch('sys.stderr', new_callable=StringIO) as err:
            self.assertEqual(m.main(args), 1)
            self.assertEqual(err.getvalue(), 'STOP: VERIFIER_ERROR\n')

    def test_cli_json_success_does_not_grant_approval(self):
        args = ['--bundle', '/unused', '--gpgv', '/gpgv', '--bsdtar', '/tar',
                '--candidate-sha256', 'a' * 64, '--candidate-bytes', '10']
        with patch.object(m.os, 'geteuid', return_value=1000, create=True), \
                patch.object(m, 'verify_runtime_bundle', return_value={'reference_approved': False}), \
                patch('sys.stdout', new_callable=StringIO) as out:
            self.assertEqual(m.main(args), 0)
            self.assertEqual(json.loads(out.getvalue()), {'reference_approved': False})


class RetainedRuntimeReportTests(unittest.TestCase):
    def report(self):
        raw = (ROOT / 'evidence/rbac/systemd-runtime-archive-host-smoke-2026-09-30.json').read_bytes()
        self.assertNotIn(b'\r', raw)
        self.assertTrue(raw.endswith(b'\n'))
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '043da749e885132c2e110beaedbf99b5cf22b4fa2ef5b31eb9863c36515b32a2')
        return json.loads(raw)

    def test_retained_report_byte_pin_package_chain_and_image_candidate_match(self):
        value = self.report()
        self.assertEqual(value['schema'], 1)
        self.assertEqual(value['package_version'], m.VERSION)
        self.assertEqual(value['archive_signer_fingerprint'], m.archive.SIGNER)
        self.assertEqual([r['package'] for r in value['packages']], ['systemd', 'libsystemd-shared'])
        self.assertEqual(value['inrelease_sha256'],
                         'c16f5e1a367bd64dbac6153facf06868e4f290483dbb4297799f71e9cce161f7')
        self.assertEqual(value['packages_xz_sha256'],
                         'a6345fd9e9a35aa81d0f058537ca44dae79ae9e50a23a40a3c6f8696453d8f3e')
        candidate = json.loads((ROOT / 'evidence/rbac/pid1-image-reference-candidate-v1.json').read_bytes())
        self.assertEqual(value['objects'][0]['sha256'], candidate['executable_sha256'])
        self.assertEqual(value['objects'][0]['bytes'], 141776)
        self.assertEqual([(o['role'], o['bytes'], o['sha256']) for o in value['objects'][1:]], [
            ('core', 2488904, '8fcb08373177707996567006be35737e408d9ede3b0a2ca08fdd130182012754'),
            ('shared', 5001176, 'c733810400659bf34b5d46f77b801507a384ebc36392c5fe48fedc72388bae3e')])

    def test_retained_loader_and_literal_shapes_do_not_prove_effective_paths(self):
        value = self.report()
        manager, core, shared = [o['elf'] for o in value['objects']]
        self.assertEqual(manager['needed'], ['libsystemd-core-259.so', 'libsystemd-shared-259.so', 'libc.so.6'])
        self.assertEqual(manager['runpath'], '/usr/lib/x86_64-linux-gnu/systemd')
        self.assertEqual(core['needed'], ['libsystemd-shared-259.so', 'libm.so.6', 'libc.so.6'])
        self.assertEqual(shared['needed'], ['libcrypt.so.1', 'libcrypto.so.3', 'libm.so.6', 'libc.so.6',
                                            'ld-linux-x86-64.so.2'])
        self.assertEqual(tuple(r['literal'] for r in value['literal_observations']), m.LITERALS)
        self.assertTrue(all(r['nul_terminated_suffix_counts'] == {'manager': 0, 'core': 0, 'shared': 1}
                            for r in value['literal_observations']))
        for name, val in value.items():
            if type(val) is bool:
                self.assertEqual(val, name in ('candidate_image_bytes_match', 'review_required'), name)

    def test_public_tools_not_imported_into_runtime_controller_or_guard(self):
        for name in ('operator_maintenance_control.py', 'operator_guard_entry.py',
                     'operator_maintenance_pid1_reference.py', 'operator_maintenance_generators.py'):
            source = (ROOT / 'siem/rbac/broker_tls' / name).read_text(encoding='utf-8')
            for forbidden in ('verify_systemd_runtime_archive', 'inspect_systemd_elf',
                              'systemd-runtime-archive-host-smoke-2026-09-30.json'):
                self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
