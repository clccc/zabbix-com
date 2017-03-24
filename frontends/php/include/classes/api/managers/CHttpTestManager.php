<?php
/*
** Zabbix
** Copyright (C) 2001-2017 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/


/**
 * Class to perform low level http tests related actions.
 */
class CHttpTestManager {

	const ITEM_HISTORY = 30;
	const ITEM_TRENDS = 90;

	/**
	 * Changed steps names.
	 * array(
	 *   testid1 => array(nameold1 => namenew1, nameold2 => namenew2),
	 *   ...
	 * )
	 *
	 * @var array
	 */
	protected $changedSteps = [];

	/**
	 * Map of parent http test id to child http test id.
	 *
	 * @var array
	 */
	protected $httpTestParents = [];

	/**
	 * Save http test to db.
	 *
	 * @param array $httpTests
	 *
	 * @return array
	 */
	public function persist(array $httpTests) {
		$this->changedSteps = $this->findChangedStepNames($httpTests);

		$httpTests = $this->save($httpTests);
		$this->inherit($httpTests);

		return $httpTests;
	}

	/**
	 * Find steps where name was changed.
	 *
	 * @return array
	 */
	protected function findChangedStepNames(array $httpTests) {
		$httpSteps = [];
		$result = [];
		foreach ($httpTests as $httpTest) {
			if (isset($httpTest['httptestid']) && isset($httpTest['steps'])) {
				foreach ($httpTest['steps'] as $step) {
					if (isset($step['httpstepid']) && isset($step['name'])) {
						$httpSteps[$step['httpstepid']] = $step['name'];
					}
				}
			}
		}

		if (!empty($httpSteps)) {
			$dbCursor = DBselect(
				'SELECT hs.httpstepid,hs.httptestid,hs.name'.
				' FROM httpstep hs'.
				' WHERE '.dbConditionInt('hs.httpstepid', array_keys($httpSteps))
			);
			while ($dbStep = DBfetch($dbCursor)) {
				if ($httpSteps[$dbStep['httpstepid']] != $dbStep['name']) {
					$result[$dbStep['httptestid']][$httpSteps[$dbStep['httpstepid']]] = $dbStep['name'];
				}
			}
		}

		return $result;
	}

	/**
	 * Create new http tests.
	 *
	 * @param array $httpTests
	 *
	 * @return array
	 */
	public function create(array $httpTests) {
		$httpTestIds = DB::insert('httptest', $httpTests);

		foreach ($httpTests as $hnum => $httpTest) {
			$httpTests[$hnum]['httptestid'] = $httpTestIds[$hnum];
			$httpTest['httptestid'] = $httpTestIds[$hnum];

			$fields = [
				ZBX_HTTPFIELD_VARIABLE => 'variables',
				ZBX_HTTPFIELD_HEADER => 'headers'
			];
			foreach ($fields as $type => $field) {
				foreach ($httpTest[$field] as &$value) {
					$value['type'] = $type;
				}
				unset($value);
			}
			$this->createTestFieldsReal($httpTest, array_merge($httpTest['variables'], $httpTest['headers']));
			$this->createHttpTestItems($httpTest);
			$this->createStepsReal($httpTest, $httpTest['steps']);
		}

		return $httpTests;
	}

	/**
	 * Update http tests.
	 *
	 * @param array $httpTests
	 *
	 * @return array
	 */
	public function update(array $httpTests) {
		$httpTestIds = zbx_objectValues($httpTests, 'httptestid');
		$dbHttpTest = API::HttpTest()->get([
			'output' => API_OUTPUT_EXTEND,
			'httptestids' => $httpTestIds,
			'selectSteps' => API_OUTPUT_EXTEND,
			'editable' => true,
			'preservekeys' => true
		]);

		$deleteStepItemIds = [];
		$steps_create = [];
		$steps_update = [];

		$fields_create = [];

		foreach ($httpTests as $key => $httpTest) {
			DB::update('httptest', [
				'values' => $httpTest,
				'where' => ['httptestid' => $httpTest['httptestid']]
			]);

			$checkItemsUpdate = [];
			$updateFields = [];
			$itemids = [];
			$dbCheckItems = DBselect(
				'SELECT i.itemid,hi.type'.
				' FROM items i,httptestitem hi'.
				' WHERE hi.httptestid='.zbx_dbstr($httpTest['httptestid']).
					' AND hi.itemid=i.itemid'
			);
			while ($checkitem = DBfetch($dbCheckItems)) {
				$itemids[] = $checkitem['itemid'];

				if (isset($httpTest['name'])) {
					$updateFields['key_'] = $this->getTestKey($checkitem['type'], $httpTest['name']);
				}

				if (isset($httpTest['status'])) {
					$updateFields['status'] = (HTTPTEST_STATUS_ACTIVE == $httpTest['status']) ? ITEM_STATUS_ACTIVE : ITEM_STATUS_DISABLED;
				}
				if (isset($httpTest['delay'])) {
					$updateFields['delay'] = $httpTest['delay'];
				}
				if (!empty($updateFields)) {
					$checkItemsUpdate[] = [
						'values' => $updateFields,
						'where' => ['itemid' => $checkitem['itemid']]
					];
				}
			}
			DB::update('items', $checkItemsUpdate);

			if (isset($httpTest['applicationid'])) {
				$this->updateItemsApplications($itemids, $httpTest['applicationid']);
			}

			$db_http_test = $dbHttpTest[$httpTest['httptestid']];

			if (array_key_exists('steps', $httpTest)) {
				$dbSteps = zbx_toHash($db_http_test['steps'], 'httpstepid');

				foreach ($httpTest['steps'] as $webstep) {
					if (isset($webstep['httpstepid']) && isset($dbSteps[$webstep['httpstepid']])) {
						$steps_update[$key][] = $webstep;
						unset($dbSteps[$webstep['httpstepid']]);
					}
					elseif (!isset($webstep['httpstepid'])) {
						$steps_create[$key][] = $webstep;
					}

					if ($db_http_test['templateid'] != 0) {
						unset($dbSteps[$webstep['httpstepid']]);
					}
				}

				$stepidsDelete = array_keys($dbSteps);

				if (!empty($stepidsDelete)) {
					$result = DBselect(
						'SELECT hi.itemid FROM httpstepitem hi WHERE '.dbConditionInt('hi.httpstepid', $stepidsDelete)
					);

					foreach (DBfetchColumn($result, 'itemid') as $itemId) {
						$deleteStepItemIds[] = $itemId;
					}

					DB::delete('httpstep', ['httpstepid' => $stepidsDelete]);
				}

				// IF application ID was not set, use the ID from DB so new items can be linked.
				if (!array_key_exists('applicationid', $httpTest)) {
					$httpTest['applicationid'] = $db_http_test['applicationid'];
				}
				elseif (bccomp($httpTest['applicationid'], $db_http_test['applicationid'])) {
					unset($httpTest['applicationid']);
				}
			}

			$source_fields = [];

			$field_types = ['headers' => ZBX_HTTPFIELD_HEADER, 'variables' => ZBX_HTTPFIELD_VARIABLE];
			foreach ($field_types as $field_name => $field_type) {
				if (array_key_exists($field_name, $httpTest)) {
					/* Same values in same order should not be changed */
					$source = array_values($db_http_test[$field_name]);
					$target = array_values($httpTest[$field_name]);

					$invalidate = false;
					$pair_count = count($source);
					if ($pair_count === count($target)) {
						for ($i = 0; $i < $pair_count; $i++) {
							if ($source[$i]['name'] !== $target[$i]['name'] ||
								$source[$i]['value'] !== $target[$i]['value']) {
								$invalidate = true;

								break;
							}
						}

						if(!$invalidate) {
							continue;
						}
					}

					$source_fields[] = $field_type;
				}
			}

			if (!empty($source_fields)) {
				foreach ($field_types as $field_name => $fieldType) {
					if (in_array($fieldType, $source_fields)) {
						foreach ($httpTest[$field_name] as $field) {
							$field['type'] = $fieldType;
							$fields_create[$key][] = $field;
						}
					}
				}

				DB::delete('httptest_field', ['httptestid' => $httpTest['httptestid'], 'type' => $source_fields]);
			}
		}

		// Old items must be deleted prior to createStepsReal() since identical items cannot be created in DB.
		if ($deleteStepItemIds) {
			API::Item()->delete($deleteStepItemIds, true);
		}

		foreach ($httpTests as $key => $httpTest) {
			if (array_key_exists($key, $fields_create)) {
				$this->createTestFieldsReal($httpTest, $fields_create[$key]);
			}

			if (array_key_exists('steps', $httpTest)) {
				if (array_key_exists($key, $steps_update)) {
					$this->updateStepsReal($httpTest, $dbHttpTest[$httpTest['httptestid']], $steps_update[$key]);
				}

				if (array_key_exists($key, $steps_create)) {
					$this->createStepsReal($httpTest, $steps_create[$key]);
				}
			}
			else {
				if (isset($httpTest['applicationid'])) {
					$dbStepIds = DBfetchColumn(DBselect(
						'SELECT i.itemid'.
						' FROM items i'.
							' INNER JOIN httpstepitem hi ON hi.itemid=i.itemid'.
						' WHERE '.dbConditionInt('hi.httpstepid', zbx_objectValues($dbHttpTest[$httpTest['httptestid']]['steps'], 'httpstepid')))
						, 'itemid'
					);
					$this->updateItemsApplications($dbStepIds, $httpTest['applicationid']);
				}

				if (isset($httpTest['status'])) {
					$status = ($httpTest['status'] == HTTPTEST_STATUS_ACTIVE) ? ITEM_STATUS_ACTIVE : ITEM_STATUS_DISABLED;

					$itemIds = DBfetchColumn(DBselect(
						'SELECT hsi.itemid'.
							' FROM httpstep hs,httpstepitem hsi'.
							' WHERE hs.httpstepid=hsi.httpstepid'.
								' AND hs.httptestid='.zbx_dbstr($httpTest['httptestid'])
					), 'itemid');

					DB::update('items', [
						'values' => ['status' => $status],
						'where' => ['itemid' => $itemIds]
					]);
				}
			}
		}

		return $httpTests;
	}

	/**
	 * Link http tests in template to hosts.
	 *
	 * @param $templateId
	 * @param $hostIds
	 */
	public function link($templateId, $hostIds) {
		$hostIds = zbx_toArray($hostIds);

		$httpTests = API::HttpTest()->get([
			'output' => API_OUTPUT_EXTEND,
			'hostids' => $templateId,
			'selectSteps' => API_OUTPUT_EXTEND,
			'editable' => true,
			'preservekeys' => true
		]);

		$types = [
			'headers' => ZBX_HTTPFIELD_HEADER,
			'variables' => ZBX_HTTPFIELD_VARIABLE,
			'posts' => ZBX_HTTPFIELD_POST_FIELD,
			'query_fields' => ZBX_HTTPFIELD_QUERY_FIELD
		];

		foreach ($httpTests as &$httpTest) {
			foreach ($types as $field => $type) {
				if (array_key_exists($field, $httpTest) && is_array($httpTest[$field])) {
					foreach ($httpTest[$field] as &$pair) {
						$pair['type'] = $type;
					}
					unset($pair);
				}
			}

			foreach ($httpTest['steps'] as &$httpStep) {
				foreach ($types as $field => $type) {
					if (array_key_exists($field, $httpStep) && is_array($httpStep[$field])) {
						foreach ($httpStep[$field] as &$pair) {
							$pair['type'] = $type;
						}
						unset($pair);
					}
				}
			}
			unset($httpStep);
		}
		unset($httpTest);

		$this->inherit($httpTests, $hostIds);
	}

	/**
	 * Inherit passed http tests to hosts.
	 * If $hostIds is empty that means that we need to inherit all $httpTests to hosts which are linked to templates
	 * where $httpTests belong.
	 *	 *
	 * @param array $httpTests
	 * @param array $hostIds
	 *
	 * @return bool
	 */
	public function inherit(array $httpTests, array $hostIds = []) {
		$hostsTemplatesMap = $this->getChildHostsFromHttpTests($httpTests, $hostIds);
		if (empty($hostsTemplatesMap)) {
			return true;
		}

		$preparedHttpTests = $this->prepareInheritedHttpTests($httpTests, $hostsTemplatesMap);
		$inheritedHttpTests = $this->save($preparedHttpTests);
		$this->inherit($inheritedHttpTests);

		return true;
	}

	/**
	 * Get array with hosts that are linked with templates which passed http tests belong to as key and templateid that host
	 * is linked to as value.
	 * If second parameter $hostIds is not empty, result should contain only passed host ids.
	 *
	 * @param array $httpTests
	 * @param array $hostIds
	 *
	 * @return array
	 */
	protected function getChildHostsFromHttpTests(array $httpTests, array $hostIds = []) {
		$hostsTemplatesMap = [];

		$sqlWhere = $hostIds ? ' AND '.dbConditionInt('ht.hostid', $hostIds) : '';
		$dbCursor = DBselect(
			'SELECT ht.templateid,ht.hostid'.
			' FROM hosts_templates ht'.
			' WHERE '.dbConditionInt('ht.templateid', zbx_objectValues($httpTests, 'hostid')).
				$sqlWhere
		);
		while ($dbHost = DBfetch($dbCursor)) {
			$hostsTemplatesMap[$dbHost['hostid']] = $dbHost['templateid'];
		}

		return $hostsTemplatesMap;
	}

	/**
	 * Generate http tests data for inheritance.
	 * Using passed parameters decide if new http tests must be created on host or existing ones must be updated.
	 *
	 * @param array $httpTests which we need to inherit
	 * @param array $hostsTemplatesMap
	 *
	 * @throws Exception
	 * @return array with http tests, existing apps have 'httptestid' key.
	 */
	protected function prepareInheritedHttpTests(array $httpTests, array $hostsTemplatesMap) {
		$hostHttpTests = $this->getHttpTestsMapsByHostIds(array_keys($hostsTemplatesMap));

		$result = [];
		foreach ($httpTests as $httpTest) {
			$httpTestId = $httpTest['httptestid'];
			foreach ($hostHttpTests as $hostId => $hostHttpTest) {
				// if http test template is not linked to host we skip it
				if ($hostsTemplatesMap[$hostId] != $httpTest['hostid']) {
					continue;
				}

				$exHttpTest = null;
				// update by templateid
				if (isset($hostHttpTest['byTemplateId'][$httpTestId])) {
					$exHttpTest = $hostHttpTest['byTemplateId'][$httpTestId];

					// need to check templateid here too in case we update linked http test to name that already exists on linked host
					if (isset($httpTest['name']) && isset($hostHttpTest['byName'][$httpTest['name']])
							&& !idcmp($exHttpTest['templateid'], $hostHttpTest['byName'][$httpTest['name']]['templateid'])) {
						$host = DBfetch(DBselect('SELECT h.name FROM hosts h WHERE h.hostid='.zbx_dbstr($hostId)));
						throw new Exception(_s('Web scenario "%1$s" already exists on host "%2$s".', $exHttpTest['name'], $host['name']));
					}
				}
				// update by name
				else if (isset($hostHttpTest['byName'][$httpTest['name']])) {
					$exHttpTest = $hostHttpTest['byName'][$httpTest['name']];
					if ($exHttpTest['templateid'] > 0 || !$this->compareHttpSteps($httpTest, $exHttpTest)) {
						$host = DBfetch(DBselect('SELECT h.name FROM hosts h WHERE h.hostid='.zbx_dbstr($hostId)));
						throw new Exception(_s('Web scenario "%1$s" already exists on host "%2$s".', $exHttpTest['name'], $host['name']));
					}

					$this->createLinkageBetweenHttpTests($httpTestId, $exHttpTest['httptestid']);
					continue;
				}

				$newHttpTest = $httpTest;
				$newHttpTest['hostid'] = $hostId;
				$newHttpTest['templateid'] = $httpTestId;
				if ($exHttpTest) {
					$newHttpTest['httptestid'] = $exHttpTest['httptestid'];

					$this->setHttpTestParent($exHttpTest['httptestid'], $httpTestId);

					if (isset($newHttpTest['steps'])) {
						$newHttpTest['steps'] = $this->prepareHttpSteps($httpTest['steps'], $exHttpTest['httptestid']);
					}
				}
				else {
					unset($newHttpTest['httptestid']);
				}

				if (!empty($newHttpTest['applicationid'])) {
					$newHttpTest['applicationid'] = $this->findChildApplication($newHttpTest['applicationid'], $hostId);
				}

				$result[] = $newHttpTest;
			}
		}

		return $result;
	}

	/**
	 * Create linkage between two http tests.
	 * If we found existing http test by name and steps, we only add linkage, i.e. change templateid
	 *
	 * @param $parentId
	 * @param $childId
	 */
	protected function createLinkageBetweenHttpTests($parentId, $childId) {
		DB::update('httptest', [
			'values' => ['templateid' => $parentId],
			'where' => ['httptestid' => $childId]
		]);

		$dbCursor = DBselect(
			'SELECT i1.itemid AS parentid,i2.itemid AS childid'.
			' FROM httptestitem hti1,httptestitem hti2,items i1,items i2'.
			' WHERE hti1.httptestid='.zbx_dbstr($parentId).
				' AND hti2.httptestid='.zbx_dbstr($childId).
				' AND hti1.itemid=i1.itemid'.
				' AND hti2.itemid=i2.itemid'.
				' AND i1.key_=i2.key_'
		);
		while ($dbItems = DBfetch($dbCursor)) {
			DB::update('items', [
				'values' => ['templateid' => $dbItems['parentid']],
				'where' => ['itemid' => $dbItems['childid']]
			]);
		}

		$dbCursor = DBselect(
			'SELECT i1.itemid AS parentid,i2.itemid AS childid'.
			' FROM httpstepitem hsi1,httpstepitem hsi2,httpstep hs1,httpstep hs2,items i1,items i2'.
			' WHERE hs1.httptestid='.zbx_dbstr($parentId).
				' AND hs2.httptestid='.zbx_dbstr($childId).
				' AND hsi1.itemid=i1.itemid'.
				' AND hsi2.itemid=i2.itemid'.
				' AND hs1.httpstepid=hsi1.httpstepid'.
				' AND hs2.httpstepid=hsi2.httpstepid'.
				' AND i1.key_=i2.key_'
		);
		while ($dbItems = DBfetch($dbCursor)) {
			DB::update('items', [
				'values' => ['templateid' => $dbItems['parentid']],
				'where' => ['itemid' => $dbItems['childid']]
			]);
		}
	}

	/**
	 * Find application with same name on given host.
	 *
	 * @param $parentAppId
	 * @param $childHostId
	 *
	 * @return string
	 */
	protected function findChildApplication($parentAppId, $childHostId) {
		$childAppId = DBfetch(DBselect(
			'SELECT a2.applicationid'.
			' FROM applications a1'.
				' INNER JOIN applications a2 ON a1.name=a2.name'.
			' WHERE a1.applicationid='.zbx_dbstr($parentAppId).
				' AND a2.hostid='.zbx_dbstr($childHostId))
		);

		return $childAppId['applicationid'];
	}

	/**
	 * Find and set first parent id for http test.
	 *
	 * @param $id
	 * @param $parentId
	 */
	protected function setHttpTestParent($id, $parentId) {
		while (isset($this->httpTestParents[$parentId])) {
			$parentId = $this->httpTestParents[$parentId];
		}
		$this->httpTestParents[$id] = $parentId;
	}

	/**
	 * Get hosts http tests for each passed hosts.
	 * Each host has two hashes with http tests, one with name keys other with templateid keys.
	 *
	 * Resulting structure is:
	 * array(
	 *     'hostid1' => array(
	 *         'byName' => array(ht1data, ht2data, ...),
	 *         'nyTemplateId' => array(ht1data, ht2data, ...)
	 *     ), ...
	 * );
	 *
	 * @param array $hostIds
	 *
	 * @return array
	 */
	protected function getHttpTestsMapsByHostIds(array $hostIds) {
		$hostHttpTests = [];
		foreach ($hostIds as $hostid) {
			$hostHttpTests[$hostid] = ['byName' => [], 'byTemplateId' => []];
		}

		$dbCursor = DBselect(
			'SELECT ht.httptestid,ht.name,ht.hostid,ht.templateid'.
			' FROM httptest ht'.
			' WHERE '.dbConditionInt('ht.hostid', $hostIds)
		);
		while ($dbHttpTest = DBfetch($dbCursor)) {
			$hostHttpTests[$dbHttpTest['hostid']]['byName'][$dbHttpTest['name']] = $dbHttpTest;
			if ($dbHttpTest['templateid']) {
				$hostHttpTests[$dbHttpTest['hostid']]['byTemplateId'][$dbHttpTest['templateid']] = $dbHttpTest;
			}
		}

		return $hostHttpTests;
	}

	/**
	 * Compare steps for http tests.
	 *
	 * @param array $httpTest steps must be included under 'steps'
	 * @param array $exHttpTest
	 *
	 * @return bool
	 */
	protected function compareHttpSteps(array $httpTest, array $exHttpTest) {
		$firstHash = '';
		$secondHash = '';

		CArrayHelper::sort($httpTest['steps'], ['no']);
		foreach ($httpTest['steps'] as $step) {
			$firstHash .= $step['no'].$step['name'];
		}

		$dbHttpTestSteps = DBfetchArray(DBselect(
			'SELECT hs.name,hs.no'.
			' FROM httpstep hs'.
			' WHERE hs.httptestid='.zbx_dbstr($exHttpTest['httptestid'])
		));

		CArrayHelper::sort($dbHttpTestSteps, ['no']);
		foreach ($dbHttpTestSteps as $dbHttpStep) {
			$secondHash .= $dbHttpStep['no'].$dbHttpStep['name'];
		}

		return ($firstHash === $secondHash);
	}

	/**
	 * Save http tests. If http test has httptestid it gets updated otherwise a new one is created.
	 *
	 * @param array $httpTests
	 *
	 * @return array
	 */
	protected function save(array $httpTests) {
		$httpTestsCreate = [];
		$httpTestsUpdate = [];

		foreach ($httpTests as $httpTest) {
			if (isset($httpTest['httptestid'])) {
				$httpTestsUpdate[] = $httpTest;
			}
			else {
				$httpTestsCreate[] = $httpTest;
			}
		}

		if (!empty($httpTestsCreate)) {
			$newHttpTests = $this->create($httpTestsCreate);
			foreach ($newHttpTests as $num => $newHttpTest) {
				$httpTests[$num]['httptestid'] = $newHttpTest['httptestid'];
			}
		}
		if (!empty($httpTestsUpdate)) {
			$this->update($httpTestsUpdate);
		}

		return $httpTests;
	}

	/**
	 * @param array $steps
	 * @param $exHttpTestId
	 *
	 * @return array
	 */
	protected function prepareHttpSteps(array $steps, $exHttpTestId) {
		$exSteps = [];
		$dbCursor = DBselect(
			'SELECT hs.httpstepid,hs.name'.
			' FROM httpstep hs'.
			' WHERE hs.httptestid='.zbx_dbstr($exHttpTestId)
		);
		while ($dbHttpStep = DBfetch($dbCursor)) {
			$exSteps[$dbHttpStep['name']] = $dbHttpStep['httpstepid'];
		}

		$result = [];
		foreach ($steps as $step) {
			$parentTestId = $this->httpTestParents[$exHttpTestId];
			if (isset($this->changedSteps[$parentTestId][$step['name']])) {
				$stepName = $this->changedSteps[$parentTestId][$step['name']];
			}
			else {
				$stepName = $step['name'];
			}

			if (isset($exSteps[$stepName])) {
				$step['httpstepid'] = $exSteps[$stepName];
				$step['httptestid'] = $exHttpTestId;
			}

			$result[] = $step;
		}

		return $result;
	}

	/**
	 * Create items required for web scenario.
	 *
	 * @param array $httpTest
	 *
	 * @throws Exception
	 */
	protected function createHttpTestItems(array $httpTest) {
		$checkitems = [
			[
				'name'				=> 'Download speed for scenario "$1".',
				'key_'				=> $this->getTestKey(HTTPSTEP_ITEM_TYPE_IN, $httpTest['name']),
				'value_type'		=> ITEM_VALUE_TYPE_FLOAT,
				'units'				=> 'Bps',
				'httptestitemtype'	=> HTTPSTEP_ITEM_TYPE_IN
			],
			[
				'name'				=> 'Failed step of scenario "$1".',
				'key_'				=> $this->getTestKey(HTTPSTEP_ITEM_TYPE_LASTSTEP, $httpTest['name']),
				'value_type'		=> ITEM_VALUE_TYPE_UINT64,
				'units'				=> '',
				'httptestitemtype'	=> HTTPSTEP_ITEM_TYPE_LASTSTEP
			],
			[
				'name'				=> 'Last error message of scenario "$1".',
				'key_'				=> $this->getTestKey(HTTPSTEP_ITEM_TYPE_LASTERROR, $httpTest['name']),
				'value_type'		=> ITEM_VALUE_TYPE_STR,
				'units'				=> '',
				'httptestitemtype'	=> HTTPSTEP_ITEM_TYPE_LASTERROR
			]
		];

		// if this is a template scenario, fetch the parent http items to link inherited items to them
		$parentItems = [];
		if (isset($httpTest['templateid']) && $httpTest['templateid']) {
			$parentItems = DBfetchArrayAssoc(DBselect(
				'SELECT i.itemid,i.key_'.
					' FROM items i,httptestitem hti'.
					' WHERE i.itemid=hti.itemid'.
					' AND hti.httptestid='.zbx_dbstr($httpTest['templateid'])
			), 'key_');
		}

		$insertItems = [];

		$delay = array_key_exists('delay', $httpTest) ? $httpTest['delay'] : DB::getDefault('httptest', 'delay');
		$status = array_key_exists('status', $httpTest) ? $httpTest['status'] : DB::getDefault('httptest', 'status');

		foreach ($checkitems as $item) {
			$item['hostid'] = $httpTest['hostid'];
			$item['delay'] = $delay;
			$item['type'] = ITEM_TYPE_HTTPTEST;
			$item['history'] = self::ITEM_HISTORY;
			$item['trends'] = self::ITEM_TRENDS;
			$item['status'] = ($status == HTTPTEST_STATUS_ACTIVE)
				? ITEM_STATUS_ACTIVE
				: ITEM_STATUS_DISABLED;

			if (isset($parentItems[$item['key_']])) {
				$item['templateid'] = $parentItems[$item['key_']]['itemid'];
			}

			$insertItems[] = $item;
		}

		$newTestItemIds = DB::insert('items', $insertItems);

		if (array_key_exists('applicationid', $httpTest)) {
			$this->createItemsApplications($newTestItemIds, $httpTest['applicationid']);
		}

		$httpTestItems = [];
		foreach ($checkitems as $inum => $item) {
			$httpTestItems[] = [
				'httptestid' => $httpTest['httptestid'],
				'itemid' => $newTestItemIds[$inum],
				'type' => $item['httptestitemtype']
			];
		}
		DB::insert('httptestitem', $httpTestItems);
	}

	/**
	 * Create web scenario fields.
	 *
	 * @param $http_test
	 * @param $http_fields
	 *
	 * @throws Exception
	 */
	protected function createTestFieldsReal($http_test, $http_fields) {
		$fields = [];
		foreach ($http_fields as $http_field) {
			$fields[] = [
				'httptestid' => $http_test['httptestid'],
				'type' => $http_field['type'],
				'name' => $http_field['name'],
				'value' => $http_field['value']
			];
		}

		DB::insert('httptest_field', $fields);
	}

	/**
	 * Create web scenario fields.
	 *
	 * @param $http_step_id
	 * @param $httpfields
	 *
	 * @throws Exception
	 */
	protected function createStepFieldsReal($http_step_id, $http_fields) {
		$fields = [];

		foreach ($http_fields as $http_field) {
			$fields[] = [
				'httpstepid' => $http_step_id,
				'type' => $http_field['type'],
				'name' => $http_field['name'],
				'value' => $http_field['value']
			];
		}

		DB::insert('httpstep_field', $fields);
	}

	/**
	 * Create web scenario steps with items.
	 *
	 * @param $httpTest
	 * @param $websteps
	 *
	 * @throws Exception
	 */
	protected function createStepsReal($httpTest, $websteps) {
		foreach ($websteps as $snum => &$webstep) {
			$websteps[$snum]['httptestid'] = $httpTest['httptestid'];
			if (is_array($webstep['posts'])) {
				$webstep['post_fields'] = $webstep['posts'];
				$webstep['posts'] = '';
				$webstep['post_type'] = ZBX_POSTTYPE_FORM;
			}
			else {
				$webstep['post_fields'] = [];
				$webstep['post_type'] = ZBX_POSTTYPE_RAW;
			}
		}
		unset($webstep);

		$webstepids = DB::insert('httpstep', $websteps);

		// if this is a template scenario, fetch the parent http items to link inherited items to them
		$parentStepItems = [];
		if (isset($httpTest['templateid']) && $httpTest['templateid']) {
			$parentStepItems = DBfetchArrayAssoc(DBselect(
				'SELECT i.itemid,i.key_,hsi.httpstepid'.
				' FROM items i,httpstepitem hsi,httpstep hs'.
				' WHERE i.itemid=hsi.itemid'.
					' AND hsi.httpstepid=hs.httpstepid'.
					' AND hs.httptestid='.zbx_dbstr($httpTest['templateid'])
			), 'key_');
		}

		foreach ($websteps as $snum => $webstep) {
			$webstepid = $webstepids[$snum];

			$fields = [];
			$field_types = [
				'headers' => ZBX_HTTPFIELD_HEADER,
				'variables' => ZBX_HTTPFIELD_VARIABLE,
				'query_fields' => ZBX_HTTPFIELD_QUERY_FIELD
			];

			if ($webstep['post_type'] === ZBX_POSTTYPE_FORM) {
				$webstep['posts'] = $webstep['post_fields'];
				$field_types['posts'] = ZBX_HTTPFIELD_POST_FIELD;
				unset($webstep['post_fields']);
			}

			foreach ($field_types as $field_name => $field_type) {
				if (array_key_exists($field_name, $webstep)) {
					foreach ($webstep[$field_name] as &$field) {
						$field['type'] = $field_type;
					}
					unset($field);
					$fields = array_merge($fields, $webstep[$field_name]);
				}
			}

			$this->createStepFieldsReal($webstepid, $fields);

			$stepitems = [
				[
					'name' => 'Download speed for step "$2" of scenario "$1".',
					'key_' => $this->getStepKey(HTTPSTEP_ITEM_TYPE_IN, $httpTest['name'], $webstep['name']),
					'value_type' => ITEM_VALUE_TYPE_FLOAT,
					'units' => 'Bps',
					'httpstepitemtype' => HTTPSTEP_ITEM_TYPE_IN
				],
				[
					'name' => 'Response time for step "$2" of scenario "$1".',
					'key_' => $this->getStepKey(HTTPSTEP_ITEM_TYPE_TIME, $httpTest['name'], $webstep['name']),
					'value_type' => ITEM_VALUE_TYPE_FLOAT,
					'units' => 's',
					'httpstepitemtype' => HTTPSTEP_ITEM_TYPE_TIME
				],
				[
					'name' => 'Response code for step "$2" of scenario "$1".',
					'key_' => $this->getStepKey(HTTPSTEP_ITEM_TYPE_RSPCODE, $httpTest['name'], $webstep['name']),
					'value_type' => ITEM_VALUE_TYPE_UINT64,
					'units' => '',
					'httpstepitemtype' => HTTPSTEP_ITEM_TYPE_RSPCODE
				]
			];

			if (!isset($httpTest['delay']) || !isset($httpTest['status'])) {
				$dbTest = DBfetch(DBselect('SELECT ht.delay,ht.status FROM httptest ht WHERE ht.httptestid='.zbx_dbstr($httpTest['httptestid'])));
				$delay = $dbTest['delay'];
				$status = $dbTest['status'];
			}
			else {
				$delay = $httpTest['delay'];
				$status = $httpTest['status'];
			}

			$insertItems = [];
			$stepItemids = [];

			foreach ($stepitems as $item) {
				$item['hostid'] = $httpTest['hostid'];
				$item['delay'] = $delay;
				$item['type'] = ITEM_TYPE_HTTPTEST;
				$item['history'] = self::ITEM_HISTORY;
				$item['trends'] = self::ITEM_TRENDS;
				$item['status'] = (HTTPTEST_STATUS_ACTIVE == $status) ? ITEM_STATUS_ACTIVE : ITEM_STATUS_DISABLED;

				if (isset($parentStepItems[$item['key_']])) {
					$item['templateid'] = $parentStepItems[$item['key_']]['itemid'];
				}

				$insertItems[] = $item;
			}

			if ($insertItems) {
				$stepItemids = DB::insert('items', $insertItems);

				if (array_key_exists('applicationid', $httpTest)) {
					$this->createItemsApplications($stepItemids, $httpTest['applicationid']);
				}
			}

			$webstepitems = [];
			foreach ($stepitems as $inum => $item) {
				$webstepitems[] = [
					'httpstepid' => $webstepid,
					'itemid' => $stepItemids[$inum],
					'type' => $item['httpstepitemtype']
				];
			}
			DB::insert('httpstepitem', $webstepitems);
		}
	}

	/**
	 * Update web scenario steps.
	 *
	 * @param $httpTest
	 * @param $dbTest
	 * @param $websteps
	 *
	 * @throws Exception
	 */
	protected function updateStepsReal($httpTest, $dbTest, $websteps) {
		$item_key_parser = new CItemKey();

		// get all used keys
		$webstepids = zbx_objectValues($websteps, 'httpstepid');
		$dbKeys = DBfetchArrayAssoc(DBselect(
			'SELECT i.key_'.
			' FROM items i,httpstepitem hi'.
			' WHERE '.dbConditionInt('hi.httpstepid', $webstepids).
				' AND hi.itemid=i.itemid')
			, 'key_'
		);

		$fields_create = [];
		$field_types = [
			'headers' => ZBX_HTTPFIELD_HEADER,
			'variables' => ZBX_HTTPFIELD_VARIABLE,
			'post_fields' => ZBX_HTTPFIELD_POST_FIELD,
			'query_fields' => ZBX_HTTPFIELD_QUERY_FIELD,
		];

		$dbSteps = zbx_toHash($dbTest['steps'], 'httpstepid');
		foreach ($websteps as &$webstep) {
			if (array_key_exists('posts', $webstep)) {
				if (is_array($webstep['posts'])) {
					$webstep['post_fields'] = $webstep['posts'];
					$webstep['posts'] = '';
					$webstep['post_type'] = ZBX_POSTTYPE_FORM;
				}
				else {
					$webstep['post_fields'] = [];
					$webstep['post_type'] = ZBX_POSTTYPE_RAW;
				}
			}

			/* step should exist as it was checked before*/
			$dbStep = $dbSteps[$webstep['httpstepid']];

			$source_fields = [];
			foreach ($field_types as $field_name => $field_type) {
				if (array_key_exists($field_name, $webstep)) {
					if (array_key_exists($field_name, $dbStep)) {
						// Same values in same order should not be changed
						$source = array_values($dbStep[$field_name]);
						$target = array_values($webstep[$field_name]);

						$invalidate = false;
						$pair_count = count($source);
						if ($pair_count === count($target)) {
							for ($i = 0; $i < $pair_count; $i++) {
								if ($source[$i]['name'] !== $target[$i]['name'] ||
									$source[$i]['value'] !== $target[$i]['value']) {
									$invalidate = true;
									break;
								}
							}

							if(!$invalidate) {
								continue;
							}
						}
					}

					$source_fields[] = $field_type;
				}
			}

			if (!empty($source_fields)) {
				foreach ($field_types as $field_name => $fieldType) {
					if (in_array($fieldType, $source_fields)) {
						foreach ($webstep[$field_name] as $field) {
							$field['type'] = $fieldType;
							$fields_create[$webstep['httpstepid']][] = $field;
						}
					}
				}

				DB::delete('httpstep_field', ['httpstepid' => $webstep['httpstepid'], 'type' => $source_fields]);
			}
		}
		unset($webstep);

		foreach ($websteps as $webstep) {
			$key = $webstep['httpstepid'];

			DB::update('httpstep', [
				'values' => $webstep,
				'where' => ['httpstepid' => $key]
			]);

			if (array_key_exists($key, $fields_create)) {
				$this->createStepFieldsReal($key, $fields_create[$key]);
			}

			// update item keys
			$itemids = [];
			$stepitemsUpdate = $updateFields = [];
			$dbStepItems = DBselect(
				'SELECT i.itemid,i.key_,hi.type'.
				' FROM items i,httpstepitem hi'.
				' WHERE hi.httpstepid='.zbx_dbstr($webstep['httpstepid']).
					' AND hi.itemid=i.itemid'
			);
			while ($stepitem = DBfetch($dbStepItems)) {
				$itemids[] = $stepitem['itemid'];

				if (isset($httpTest['name']) || isset($webstep['name'])) {
					if (!isset($httpTest['name']) || !isset($webstep['name'])) {
						$item_key_parser->parse($stepitem['key_']);
						if (!isset($httpTest['name'])) {
							$httpTest['name'] = $item_key_parser->getParam(0);
						}
						if (!isset($webstep['name'])) {
							$webstep['name'] = $item_key_parser->getParam(1);
						}
					}

					$updateFields['key_'] = $this->getStepKey($stepitem['type'], $httpTest['name'], $webstep['name']);
				}
				if (isset($dbKeys[$updateFields['key_']])) {
					unset($updateFields['key_']);
				}
				if (isset($httpTest['status'])) {
					$updateFields['status'] = (HTTPTEST_STATUS_ACTIVE == $httpTest['status']) ? ITEM_STATUS_ACTIVE : ITEM_STATUS_DISABLED;
				}
				if (isset($httpTest['delay'])) {
					$updateFields['delay'] = $httpTest['delay'];
				}
				if (!empty($updateFields)) {
					$stepitemsUpdate[] = [
						'values' => $updateFields,
						'where' => ['itemid' => $stepitem['itemid']]
					];
				}
			}

			if ($stepitemsUpdate) {
				DB::update('items', $stepitemsUpdate);
			}

			if (array_key_exists('applicationid', $httpTest)) {
				$this->updateItemsApplications($itemids, $httpTest['applicationid']);
			}
		}
	}

	/**
	 * Update web item application linkage.
	 *
	 * @param array  $itemids
	 * @param string $applicationid
	 */
	protected function updateItemsApplications(array $itemids, $applicationid) {
		if ($applicationid == 0) {
			DB::delete('items_applications', ['itemid' => $itemids]);
		}
		else {
			$linked_itemids = DBfetchColumn(
				DBselect('SELECT ia.itemid FROM items_applications ia WHERE '.dbConditionInt('ia.itemid', $itemids)),
				'itemid'
			);

			if ($linked_itemids) {
				DB::update('items_applications', [
					'values' => ['applicationid' => $applicationid],
					'where' => ['itemid' => $linked_itemids]
				]);
			}

			$this->createItemsApplications(array_diff($itemids, $linked_itemids), $applicationid);
		}
	}

	/**
	 * Create web item application linkage.
	 *
	 * @param array  $itemids
	 * @param string $applicationid
	 */
	protected function createItemsApplications(array $itemids, $applicationid) {
		if ($applicationid != 0 && $itemids) {
			$insert = [];

			foreach ($itemids as $itemid) {
				$insert[] = ['itemid' => $itemid, 'applicationid' => $applicationid];
			}

			DB::insertBatch('items_applications', $insert);
		}
	}

	/**
	 * Get item key for test item.
	 *
	 * @param int    $type
	 * @param string $testName
	 *
	 * @return bool|string
	 */
	protected function getTestKey($type, $testName) {
		switch ($type) {
			case HTTPSTEP_ITEM_TYPE_IN:
				return 'web.test.in['.quoteItemKeyParam($testName).',,bps]';
			case HTTPSTEP_ITEM_TYPE_LASTSTEP:
				return 'web.test.fail['.quoteItemKeyParam($testName).']';
			case HTTPSTEP_ITEM_TYPE_LASTERROR:
				return 'web.test.error['.quoteItemKeyParam($testName).']';
		}

		return false;
	}

	/**
	 * Get item key for step item.
	 *
	 * @param int    $type
	 * @param string $testName
	 * @param string $stepName
	 *
	 * @return bool|string
	 */
	protected function getStepKey($type, $testName, $stepName) {
		switch ($type) {
			case HTTPSTEP_ITEM_TYPE_IN:
				return 'web.test.in['.quoteItemKeyParam($testName).','.quoteItemKeyParam($stepName).',bps]';
			case HTTPSTEP_ITEM_TYPE_TIME:
				return 'web.test.time['.quoteItemKeyParam($testName).','.quoteItemKeyParam($stepName).',resp]';
			case HTTPSTEP_ITEM_TYPE_RSPCODE:
				return 'web.test.rspcode['.quoteItemKeyParam($testName).','.quoteItemKeyParam($stepName).']';
		}

		return false;
	}

	/**
	 * Returns the data about the last execution of the given HTTP tests.
	 *
	 * The following values will be returned for each executed HTTP test:
	 * - lastcheck      - time when the test has been executed last
	 * - lastfailedstep - number of the last failed step
	 * - error          - error message
	 *
	 * If a HTTP test has not been executed in last ZBX_HISTORY_PERIOD, no value will be returned.
	 *
	 * @param array $httpTestIds
	 *
	 * @return array    an array with HTTP test IDs as keys and arrays of data as values
	 */
	public function getLastData(array $httpTestIds) {
		$httpItems = DBfetchArray(DBselect(
			'SELECT hti.httptestid,hti.type,i.itemid,i.value_type'.
			' FROM httptestitem hti,items i'.
			' WHERE hti.itemid=i.itemid'.
				' AND hti.type IN ('.HTTPSTEP_ITEM_TYPE_LASTSTEP.','.HTTPSTEP_ITEM_TYPE_LASTERROR.')'.
				' AND '.dbConditionInt('hti.httptestid', $httpTestIds)
		));

		$history = Manager::History()->getLast($httpItems, 1, ZBX_HISTORY_PERIOD);

		$data = [];

		foreach ($httpItems as $httpItem) {
			if (isset($history[$httpItem['itemid']])) {
				if (!isset($data[$httpItem['httptestid']])) {
					$data[$httpItem['httptestid']] = [
						'lastcheck' => null,
						'lastfailedstep' => null,
						'error' => null
					];
				}

				$itemHistory = $history[$httpItem['itemid']][0];

				if ($httpItem['type'] == HTTPSTEP_ITEM_TYPE_LASTSTEP) {
					$data[$httpItem['httptestid']]['lastcheck'] = $itemHistory['clock'];
					$data[$httpItem['httptestid']]['lastfailedstep'] = $itemHistory['value'];
				}
				else {
					$data[$httpItem['httptestid']]['error'] = $itemHistory['value'];
				}
			}
		}

		return $data;
	}
}
