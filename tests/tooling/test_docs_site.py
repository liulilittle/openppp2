import tempfile
import unittest
from pathlib import Path

from tools.docs_site import DocsSite, canonical, check_links, heading_ids, included


class DocsSiteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.files = {
            'docs/README.md': '# Tasks\n[Chinese](README_CN.md)\n',
            'docs/README_CN.md': '# 任务\n[English](README.md)\n',
            'docs/guides/README.md': '# Guides\n',
            'docs/guides/README_CN.md': '# 指南\n',
            'docs/guides/PAIR.md': '# Pair\n## A title\n',
            'docs/guides/PAIR_CN.md': '# 配对\n## 中文标题\n',
            'docs/guides/ONLY.md': '# English only\n',
            'docs/design/ONLY_CN.md': '# 中文设计\n',
            'docs/archive/audits/OLD.md': '# Old audit\n> Status: Historical\n',
            'docs/development/BOOST_187_COMPATIBILITY.md': '# Boost 审计\n',
            'docs/guides/image.svg': '<svg/>',
            'docs/archive/untracked/PRIVATE.md': '# Private\n',
            'docs/superpowers/plans/AGENT.md': '# Agent\n',
            'docs/build/generated.md': '# Generated\n',
            'docs/AGENTS.md': '# Instructions\n',
            'README.md': '# Repository\n',
        }
        for relative, text in self.files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.site = DocsSite(self.root)
        self.site.discover([Path(p) for p in self.files if p.startswith('docs/')])

    def test_pairs_and_homepages_share_paths(self):
        self.assertEqual(Path('index.md'), canonical(Path('README_CN.md')))
        self.assertEqual(Path('guides/index.md'), canonical(Path('guides/README.md')))
        variants = self.site.sources[Path('guides/PAIR.md')]
        self.assertEqual({'en', 'zh'}, set(variants))
        self.assertEqual(Path('guides/PAIR_CN.md'), self.site.selected(Path('guides/PAIR.md'), 'zh'))

    def test_unpaired_documents_preserve_original_language(self):
        english = self.site.render(Path('guides/ONLY.md'), 'zh')
        self.assertIn('仅有英文版本', english)
        self.assertIn('# English only', english)
        chinese = self.site.render(Path('design/ONLY.md'), 'en')
        self.assertIn('available only in Chinese', chinese)
        self.assertIn('# 中文设计', chinese)
        audit = self.site.render(Path('development/BOOST_187_COMPATIBILITY.md'), 'en')
        self.assertIn('available only in Chinese', audit)

    def test_cross_language_and_directory_links(self):
        source = Path('guides/PAIR.md')
        self.assertEqual('/openppp2/zh/guides/PAIR/#中文标题', self.site.destination('PAIR_CN.md#中文标题', source, 'en'))
        self.assertEqual('/openppp2/guides/', self.site.destination('README.md', source, 'en'))
        self.assertEqual('/openppp2/', self.site.destination('../README.md', source, 'en'))
        self.assertEqual('/openppp2/zh/guides/ONLY/', self.site.destination('ONLY.md', source, 'zh'))
        self.assertEqual('/openppp2/guides/PAIR/', self.site.destination('PAIR.md', Path('guides/PAIR_CN.md'), 'zh'))

    def test_assets_and_repository_links(self):
        source = Path('guides/PAIR.md')
        self.assertEqual('/openppp2/zh/guides/image.svg', self.site.destination('image.svg', source, 'zh'))
        self.assertEqual('https://github.com/Miaocchi/openppp2/blob/main/README.md', self.site.destination('../../README.md', source, 'en'))
        self.assertEqual('https://example.com/a?q=1#x', self.site.destination('https://example.com/a?q=1#x', source, 'en'))

    def test_rewrite_preserves_examples_and_handles_reference_and_html_links(self):
        text = ('[Pair](PAIR_CN.md#中文标题)\n'
                '`[Example](PAIR_CN.md)`\n'
                '````markdown\n[Example](PAIR_CN.md)\n```\n````\n'
                '    [Indented](PAIR_CN.md)\n'
                '[ref]: PAIR_CN.md "Title"\n'
                '<img src="image.svg">\n')
        result = self.site.rewrite(text, Path('guides/PAIR.md'), 'en')
        self.assertIn('[Pair](/openppp2/zh/guides/PAIR/#中文标题)', result)
        self.assertIn('`[Example](PAIR_CN.md)`', result)
        self.assertIn('````markdown\n[Example](PAIR_CN.md)\n```\n````', result)
        self.assertIn('    [Indented](PAIR_CN.md)', result)
        self.assertIn('[ref]: /openppp2/zh/guides/PAIR/ "Title"', result)
        self.assertIn('<img src="/openppp2/guides/image.svg">', result)

    def test_unicode_heading_ids_and_duplicate_fragments(self):
        result = heading_ids('# 中文标题\n## 中文标题\n## `ppp` 参数！\n')
        self.assertIn('{#中文标题}', result)
        self.assertIn('{#中文标题-1}', result)
        self.assertIn('{#ppp-参数}', result)
        self.assertEqual('## Already {#custom}\n', heading_ids('## Already {#custom}\n'))

    def test_exclusion_and_history(self):
        for path in ('archive/untracked/PRIVATE.md', 'superpowers/plans/AGENT.md', 'build/generated.md', 'AGENTS.md'):
            self.assertFalse(included(Path(path)))
            self.assertNotIn(canonical(Path(path)), self.site.sources)
        rendered = self.site.render(Path('archive/audits/OLD.md'), 'en')
        self.assertIn('exclude: true', rendered)
        self.assertIn('Historical material', rendered)
        self.assertIn('> Status: Historical', rendered)

    def test_repeat_preparation_removes_stale_inputs_and_output(self):
        import shutil
        from tools.docs_site import ROOT
        shutil.copy2(ROOT / 'zensical.toml', self.root / 'zensical.toml')
        shutil.copytree(ROOT / 'tools/docs_theme', self.root / 'tools/docs_theme')
        self.site.prepare()
        stale_input = self.site.work / 'en/docs/REMOVED.md'
        stale_input.write_text('# Removed')
        stale_output = self.site.work / 'site/stale/index.html'
        stale_output.parent.mkdir(parents=True)
        stale_output.write_text('stale')
        self.site.prepare()
        self.assertFalse(stale_input.exists())
        self.assertFalse(stale_output.exists())
        self.assertTrue((self.site.work / 'zh/docs/guides/PAIR.md').exists())

    def test_generated_link_checker_covers_base_paths_assets_and_fragments(self):
        site = self.root / 'site'
        (site / 'zh').mkdir(parents=True)
        (site / 'index.html').write_text('<a href="/openppp2/zh/#中文">中文</a><img src="a.svg">')
        (site / 'a.svg').write_text('<svg/>')
        (site / 'zh/index.html').write_text('<h1 id="中文">中文</h1><a href="../">English</a>')
        self.assertEqual([], check_links(site, '/openppp2/'))
        (site / 'index.html').write_text('<a href="/zh/">wrong base</a><a href="zh/#missing">bad anchor</a><img src="missing.svg">')
        errors = check_links(site, '/openppp2/')
        self.assertEqual(3, len(errors))
        self.assertTrue(any('missing anchor' in error for error in errors))


if __name__ == '__main__':
    unittest.main()
