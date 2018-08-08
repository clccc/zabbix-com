<?php
/*
** Zabbix
** Copyright (C) 2001-2018 Zabbix SIA
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


class CSvgTag extends CTag {

	const ZBX_STYLE_GRAPH_DASHED = 'svg-graph-dashed';

	const ZBX_STYLE_GRAPH_PROBLEMS = 'svg-graph-problems';
	const ZBX_STYLE_GRAPH_PROBLEM_BOX = 'svg-graph-problem-box';
	const ZBX_STYLE_GRAPH_PROBLEM_HANDLE = 'svg-graph-problem-handle';
	const ZBX_STYLE_GRAPH_PROBLEM_ARROW = 'svg-graph-problem-arrow';

	const ZBX_STYLE_GRAPH_AXIS = 'svg-graph-axis';
	const ZBX_STYLE_GRAPH_AXIS_LEFT = 'svg-graph-axis-left';
	const ZBX_STYLE_GRAPH_AXIS_RIGHT = 'svg-graph-axis-right';
	const ZBX_STYLE_GRAPH_AXIS_BOTTOM = 'svg-graph-axis-bottom';

	const ZBX_STYLE_SVG_GRAPH_AREA = 'svg-graph-area';
	const ZBX_STYLE_SVG_GRAPH_GRID = 'svg-graph-grid';
	const ZBX_STYLE_SVG_GRAPH_LINE = 'svg-graph-line';
	const ZBX_STYLE_SVG_GRAPH_POINTS = 'svg-graph-points';

	const ZBX_STYLE_GRAPH_LEGEND = 'svg-graph-legend';

	/**
	 * SVG styles array.
	 */
	protected $styles = [];

	protected $width = 0;
	protected $height = 0;
	protected $x = 0;
	protected $y = 0;

	public function __construct($tag) {
		parent::__construct($tag, true);
	}

	public function getStyles() {
		return $this->styles;
	}

	/**
	 * Add child item with styles.
	 *
	 * @param string|array|CSvgTag    Child item.
	 *
	 * @return CSvgTag
	 */
	public function addItem($value) {
		if ($value instanceof CSvgTag) {
			$this->styles = $value->getStyles() + $this->styles;
		}

		return parent::addItem($value);
	}


	/**
	 * Set axis container size.
	 *
	 * @param int $width    Axis container width.
	 * @param int $height   Axis container height.
	 *
	 * @return CSvgTag
	 */
	public function setSize($width, $height) {
		$this->width = $width;
		$this->height = $height;

		return $this;
	}

	/**
	 * Set axis container position.
	 *
	 * @param int $x        Horizontal position of container element.
	 * @param int $y        Veritical position of container element.
	 *
	 * @return CSvgTag
	 */
	public function setPosition($x, $y) {
		$this->x = (int) $x;
		$this->y = (int) $y;

		return $this;
	}

	public function setFillColor($color) {
		$this->setAttribute('fill', $color);

		return $this;
	}

	public function setStrokeColor($color) {
		$this->setAttribute('stroke', $color);

		return $this;
	}

	public function setStrokeWidth($width) {
		$this->setAttribute('stroke-width', $width);

		return $this;
	}

	public function setFillOpacity($opacity) {
		$this->setAttribute('fill-opacity', $opacity);

		return $this;
	}

	public function setStrokeOpacity($opacity) {
		$this->setAttribute('stroke-opacity', $opacity);

		return $this;
	}
}
