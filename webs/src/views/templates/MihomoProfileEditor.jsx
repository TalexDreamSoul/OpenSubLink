import { useMemo, useState } from 'react';
import { Alert, Button, FormControlLabel, MenuItem, Stack, Switch, TextField, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import { isMap, isSeq, parseDocument } from 'yaml';

const groupTypes = ['select', 'url-test', 'fallback', 'load-balance', 'relay'];
const groupKey = 'proxy-groups';
const ruleKey = 'rules';
const scalarText = (value) => (typeof value === 'string' ? value : '');

export default function MihomoProfileEditor({ text, onChange }) {
  const { t } = useTranslation();
  const [groupIndex, setGroupIndex] = useState(0);
  const [ruleIndex, setRuleIndex] = useState(0);
  const [newRule, setNewRule] = useState('');
  const document = useMemo(() => parseDocument(text || '{}'), [text]);
  const groups = document.get(groupKey, true);
  const rules = document.get(ruleKey, true);
  const invalid =
    document.errors.length ||
    (document.contents !== null && !isMap(document.contents)) ||
    (groups != null && !isSeq(groups)) ||
    (rules != null && !isSeq(rules));

  if (invalid) {
    return <Alert severity="warning">{t('templates.profile.invalid')}</Alert>;
  }

  const groupEntries = groups?.items ?? [];
  const ruleEntries = rules?.items ?? [];
  const selectedGroup = Math.min(groupIndex, groupEntries.length - 1);
  const selectedRule = Math.min(ruleIndex, ruleEntries.length - 1);
  const group = groupEntries[selectedGroup];
  const groupType = isMap(group) ? scalarText(group.get('type')) || 'select' : '';
  const members = isMap(group) ? group.get('proxies', true) : undefined;
  const existingTypes = groupTypes.includes(groupType) ? groupTypes : [...groupTypes, groupType];

  const update = (mutate) => {
    const draft = document.clone();
    if (draft.contents === null) draft.contents = draft.createNode({});
    mutate(draft);
    onChange(draft.toString({ lineWidth: 0 }));
  };

  const append = (draft, key, value) => {
    if (!draft.has(key) || draft.get(key) == null) draft.set(key, []);
    draft.addIn([key], value);
  };

  const updateGroup = (key, value) => update((draft) => draft.setIn([groupKey, selectedGroup, key], value));

  const addGroup = () => {
    const names = new Set(groupEntries.map((item) => (isMap(item) ? item.get('name') : undefined)));
    let index = groupEntries.length + 1;
    let name = t('templates.profile.newGroupName', { index });
    while (names.has(name)) {
      index += 1;
      name = t('templates.profile.newGroupName', { index });
    }
    update((draft) => append(draft, groupKey, { name, type: 'select', proxies: ['DIRECT'] }));
    setGroupIndex(groupEntries.length);
  };

  const moveRule = (offset) => {
    const target = selectedRule + offset;
    update((draft) => {
      const entries = draft.get(ruleKey, true).items;
      const [rule] = entries.splice(selectedRule, 1);
      entries.splice(target, 0, rule);
    });
    setRuleIndex(target);
  };

  const addRule = () => {
    const value = newRule.trim();
    if (!value) return;
    const catchAll = ruleEntries.findIndex((rule) => /^MATCH,/i.test(scalarText(rule?.value)));
    const index = catchAll === -1 ? ruleEntries.length : catchAll;
    update((draft) => {
      if (index === ruleEntries.length) append(draft, ruleKey, value);
      else draft.get(ruleKey, true).items.splice(index, 0, draft.createNode(value));
    });
    setRuleIndex(index);
    setNewRule('');
  };

  return (
    <Stack spacing={2}>
      <Stack direction={{ xs: 'column', sm: 'row' }}>
        {['dns', 'tun'].map((key) => {
          const section = document.get(key, true);
          return (
            <FormControlLabel
              key={key}
              label={t(`templates.profile.${key}`)}
              control={
                <Switch
                  checked={document.getIn([key, 'enable']) === true}
                  disabled={section != null && !isMap(section)}
                  onChange={(_, enabled) => update((draft) => draft.setIn([key, 'enable'], enabled))}
                />
              }
            />
          );
        })}
      </Stack>
      <Stack spacing={1.5}>
        <Typography variant="subtitle2">{t('templates.profile.groups')}</Typography>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
          {groupEntries.length > 0 && (
            <TextField
              select
              fullWidth
              size="small"
              label={t('templates.profile.selectedGroup')}
              value={selectedGroup}
              onChange={(event) => setGroupIndex(Number(event.target.value))}
            >
              {groupEntries.map((item, index) => (
                <MenuItem key={index} value={index}>
                  {(isMap(item) && scalarText(item.get('name'))) || `#${index + 1}`}
                </MenuItem>
              ))}
            </TextField>
          )}
          <Button sx={{ flexShrink: 0 }} onClick={addGroup}>
            {t('templates.profile.addGroup')}
          </Button>
        </Stack>
        {isMap(group) && (
          <Stack spacing={1.5} key={selectedGroup}>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
              <TextField
                fullWidth
                size="small"
                label={t('templates.profile.groupName')}
                defaultValue={scalarText(group.get('name'))}
                key={`name:${scalarText(group.get('name'))}`}
                onBlur={(event) => {
                  const name = event.target.value.trim();
                  const oldName = scalarText(group.get('name'));
                  if (
                    name &&
                    !name.includes(',') &&
                    name !== oldName &&
                    !groupEntries.some((item) => isMap(item) && item.get('name') === name)
                  ) {
                    update((draft) => {
                      draft.setIn([groupKey, selectedGroup, 'name'], name);
                      if (!oldName) return;
                      for (const entry of draft.get(groupKey, true).items) {
                        if (!isMap(entry)) continue;
                        const proxies = entry.get('proxies', true);
                        if (!isSeq(proxies)) continue;
                        for (const proxy of proxies.items) {
                          if (proxy?.value === oldName) proxy.value = name;
                        }
                      }
                      const entries = draft.get(ruleKey, true);
                      if (!isSeq(entries)) return;
                      for (const rule of entries.items) {
                        if (typeof rule?.value !== 'string') continue;
                        const tail = rule.value.endsWith(',no-resolve') ? ',no-resolve' : '';
                        const value = tail ? rule.value.slice(0, -tail.length) : rule.value;
                        const split = value.lastIndexOf(',');
                        if (split >= 0 && value.slice(split + 1).trim() === oldName) {
                          rule.value = `${value.slice(0, split + 1)}${name}${tail}`;
                        }
                      }
                    });
                  } else {
                    event.target.value = oldName;
                  }
                }}
              />
              <TextField
                select
                fullWidth
                size="small"
                label={t('templates.profile.groupType')}
                value={groupType}
                onChange={(event) => {
                  const type = event.target.value;
                  update((draft) => {
                    const groupPath = [groupKey, selectedGroup];
                    draft.setIn([...groupPath, 'type'], type);
                    if (['url-test', 'fallback', 'load-balance'].includes(type) && !draft.getIn([...groupPath, 'url'])) {
                      draft.setIn([...groupPath, 'url'], 'https://www.gstatic.com/generate_204');
                      draft.setIn([...groupPath, 'interval'], 300);
                    }
                  });
                }}
              >
                {existingTypes.map((type) => (
                  <MenuItem key={type} value={type}>
                    {type}
                  </MenuItem>
                ))}
              </TextField>
            </Stack>
            <TextField
              fullWidth
              size="small"
              label={t('templates.profile.filter')}
              defaultValue={scalarText(group.get('filter'))}
              key={`filter:${scalarText(group.get('filter'))}`}
              onBlur={(event) => {
                const filter = event.target.value.trim();
                if (filter === scalarText(group.get('filter'))) return;
                if (filter) updateGroup('filter', filter);
                else update((draft) => draft.deleteIn([groupKey, selectedGroup, 'filter']));
              }}
            />
            <FormControlLabel
              label={t('templates.profile.includeProxies')}
              control={
                <Switch
                  checked={group.get('include-all-proxies') === true}
                  onChange={(_, enabled) => updateGroup('include-all-proxies', enabled)}
                />
              }
            />
            {(members == null || isSeq(members)) && (
              <TextField
                fullWidth
                multiline
                minRows={2}
                maxRows={6}
                size="small"
                label={t('templates.profile.members')}
                defaultValue={members?.items.map((item) => scalarText(item?.value)).join('\n') || ''}
                key={`members:${String(members ?? '')}`}
                onBlur={(event) => {
                  const next = event.target.value
                    .split('\n')
                    .map((item) => item.trim())
                    .filter(Boolean);
                  const current = members?.items.map((item) => item?.value) ?? [];
                  if (JSON.stringify(next) !== JSON.stringify(current)) updateGroup('proxies', next);
                }}
              />
            )}
          </Stack>
        )}
      </Stack>
      <Stack spacing={1}>
        <Typography variant="subtitle2">{t('templates.profile.rules')}</Typography>
        {ruleEntries.length > 0 && (
          <>
            <TextField
              select
              size="small"
              label={t('templates.profile.selectedRule')}
              value={selectedRule}
              onChange={(event) => setRuleIndex(Number(event.target.value))}
            >
              {ruleEntries.map((rule, index) => (
                <MenuItem key={index} value={index}>
                  {index + 1}. {scalarText(rule?.value) || '…'}
                </MenuItem>
              ))}
            </TextField>
            <Stack direction="row" flexWrap="wrap" gap={1}>
              <Button disabled={selectedRule <= 0} onClick={() => moveRule(-1)}>
                {t('templates.profile.moveUp')}
              </Button>
              <Button disabled={selectedRule >= ruleEntries.length - 1} onClick={() => moveRule(1)}>
                {t('templates.profile.moveDown')}
              </Button>
              <Button color="error" onClick={() => update((draft) => draft.deleteIn([ruleKey, selectedRule]))}>
                {t('templates.profile.removeRule')}
              </Button>
            </Stack>
          </>
        )}
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
          <TextField
            fullWidth
            size="small"
            label={t('templates.profile.newRule')}
            value={newRule}
            onChange={(event) => setNewRule(event.target.value)}
          />
          <Button sx={{ flexShrink: 0 }} disabled={!newRule.trim()} onClick={addRule}>
            {t('templates.profile.addRule')}
          </Button>
        </Stack>
      </Stack>
    </Stack>
  );
}
