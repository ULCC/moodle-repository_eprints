<?php

/**
 * @since 2.0
 * @package    repository_eprints
 * @copyright  2012 Greg Pasciak/ULCC
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */


require_once($CFG->dirroot . '/repository/lib.php');
require_once($CFG->dirroot . '/repository/eprintssd/epclient.php');



class repository_eprints extends repository {
    private $mimetypes = array();

    /**
     * Print a upload form
     * @return array
     */
    public function print_login() {
        return $this->get_listing();
    }

    /**
     * Process uploaded file
     * @return array|bool
     */
    public function upload($saveas_filename, $maxbytes) {
        global $CFG;

        $types = optional_param_array('accepted_types', '*', PARAM_RAW);
        $savepath = optional_param('savepath', '/', PARAM_PATH);
        $itemid   = optional_param('itemid', 0, PARAM_INT);
        $license  = optional_param('license', $CFG->sitedefaultlicense, PARAM_TEXT);
        $author   = optional_param('author', '', PARAM_TEXT);
        $title    = optional_param('title', '', PARAM_TEXT);
        $metadata = optional_param('metadata', '', PARAM_TEXT);
        $overwriteexisting = optional_param('overwrite', true, PARAM_BOOL);

        return $this->process_eprints($saveas_filename, $maxbytes, $types, $savepath, $itemid, $license, $author, $title, $overwriteexisting, $metadata);
    }

    /**
     * Do the actual processing of the uploaded file
     * @param string $saveas_filename name to give to the file
     * @param int $maxbytes maximum file size
     * @param mixed $types optional array of file extensions that are allowed or '*' for all
     * @param string $savepath optional path to save the file to
     * @param int $itemid optional the ID for this item within the file area
     * @param string $license optional the license to use for this file
     * @param string $author optional the name of the author of this file
     * @param bool $overwriteexisting optional user has asked to overwrite the existing file
     * @return object containing details of the file uploaded
     */
    public function process_eprints($saveas_filename, $maxbytes, $types = '*', $savepath = '/', $itemid = 0, $license = null, $author = '', $title = '', $overwriteexisting = false, $metadata='') {
        global $USER, $CFG;

        if ((is_array($types) and in_array('*', $types)) or $types == '*') {
            $this->mimetypes = '*';
        } else {
            foreach ($types as $type) {
                $this->mimetypes[] = mimeinfo('type', $type);
            }
        }

        if ($license == null) {
            $license = $CFG->sitedefaultlicense;
        }
//--------------gregp---------------------------------------------

        $record = new EpClient();
        $record->title   = $title;
        $record->creators_name = $author;
        $record->date = time();
        $record->url_file = $savepath;
        $record->type   = $itemid;
        $result_put = $record->put();

        $context = context_user::instance($USER->id);
        $elname = 'eprints_upload_file';

        $fs = get_file_storage();
        $sm = get_string_manager();

        if ($record->filepath !== '/') {
            $record->filepath = file_correct_filepath($record->filepath);
        }

        if (!isset($_FILES[$elname])) {
            throw new moodle_exception('nofile');
        }
        if (!empty($_FILES[$elname]['error'])) {
            switch ($_FILES[$elname]['error']) {
            case UPLOAD_ERR_INI_SIZE:
                throw new moodle_exception('upload_error_ini_size', 'repository_eprints');
                break;
            case UPLOAD_ERR_FORM_SIZE:
                throw new moodle_exception('upload_error_form_size', 'repository_eprints');
                break;
            case UPLOAD_ERR_PARTIAL:
                throw new moodle_exception('upload_error_partial', 'repository_eprints');
                break;
            case UPLOAD_ERR_NO_FILE:
                throw new moodle_exception('upload_error_no_file', 'repository_eprints');
                break;
            case UPLOAD_ERR_NO_TMP_DIR:
                throw new moodle_exception('upload_error_no_tmp_dir', 'repository_eprints');
                break;
            case UPLOAD_ERR_CANT_WRITE:
                throw new moodle_exception('upload_error_cant_write', 'repository_eprints');
                break;
            case UPLOAD_ERR_EXTENSION:
                throw new moodle_exception('upload_error_extension', 'repository_eprints');
                break;
            default:
                throw new moodle_exception('nofile');
            }
        }

        // scan the files, throws exception and deletes if virus found
        // this is tricky because clamdscan daemon might not be able to access the files
        $permissions = fileperms($_FILES[$elname]['tmp_name']);
        @chmod($_FILES[$elname]['tmp_name'], $CFG->filepermissions);
        self::antivir_scan_file($_FILES[$elname]['tmp_name'], $_FILES[$elname]['name'], true);
        @chmod($_FILES[$elname]['tmp_name'], $permissions);

        // {@link repository::build_source_field()}
        $sourcefield = $this->get_file_source_info($_FILES[$elname]['name']);
        $record->source = self::build_source_field($sourcefield);

        if (empty($saveas_filename)) {
            $record->filename = clean_param($_FILES[$elname]['name'], PARAM_FILE);
        } else {
            $ext = '';
            $match = array();
            $filename = clean_param($_FILES[$elname]['name'], PARAM_FILE);
            if (strpos($filename, '.') === false) {
                // File has no extension at all - do not add a dot.
                $record->filename = $saveas_filename;
            } else {
                if (preg_match('/\.([a-z0-9]+)$/i', $filename, $match)) {
                    if (isset($match[1])) {
                        $ext = $match[1];
                    }
                }
                $ext = !empty($ext) ? $ext : '';
                if (preg_match('#\.(' . $ext . ')$#i', $saveas_filename)) {
                    // saveas filename contains file extension already
                    $record->filename = $saveas_filename;
                } else {
                    $record->filename = $saveas_filename . '.' . $ext;
                }
            }
        }

        // Check the file has some non-null contents - usually an indication that a user has
        // tried to upload a folder by mistake
        if (!$this->check_valid_contents($_FILES[$elname]['tmp_name'])) {
            throw new moodle_exception('upload_error_invalid_file', 'repository_eprints', '', $record->filename);
        }

        if ($this->mimetypes != '*') {
            // check filetype
            $filemimetype = file_storage::mimetype($_FILES[$elname]['tmp_name'], $record->filename);
            if (!in_array($filemimetype, $this->mimetypes)) {
                throw new moodle_exception('invalidfiletype', 'repository', '', get_mimetype_description(array('filename' => $_FILES[$elname]['name'])));
            }
        }

        if (empty($record->itemid)) {
            $record->itemid = 0;
        }

        if (($maxbytes!==-1) && (filesize($_FILES[$elname]['tmp_name']) > $maxbytes)) {
            throw new file_exception('maxbytes');
        }
        $record->contextid = $context->id;
        $record->userid    = $USER->id;

        if (repository::draftfile_exists($record->itemid, $record->filepath, $record->filename)) {
            if ($overwriteexisting) {
                repository::delete_tempfile_from_draft($record->itemid, $record->filepath, $record->filename);
            } else {
                $existingfilename = $record->filename;
                $unused_filename = repository::get_unused_filename($record->itemid, $record->filepath, $record->filename);
                $record->filename = $unused_filename;
                $stored_file = $fs->create_file_from_pathname($record, $_FILES[$elname]['tmp_name']);
                $event = array();
                $event['event'] = 'fileexists';
                $event['newfile'] = new stdClass;
                $event['newfile']->filepath = $record->filepath;
                $event['newfile']->filename = $unused_filename;
                $event['newfile']->url = moodle_url::make_draftfile_url($record->itemid, $record->filepath, $unused_filename)->out(false);

                $event['existingfile'] = new stdClass;
                $event['existingfile']->filepath = $record->filepath;
                $event['existingfile']->filename = $existingfilename;
                $event['existingfile']->url      = moodle_url::make_draftfile_url($record->itemid, $record->filepath, $existingfilename)->out(false);
                return $event;
            }
        }

        $stored_file = $fs->create_file_from_pathname($record, $_FILES[$elname]['tmp_name']);

        return array(
            'url'=>moodle_url::make_draftfile_url($record->itemid, $record->filepath, $record->filename)->out(false),
            'id'=>$record->itemid,
            'file'=>$record->filename);
    }


    /**
     * Checks the contents of the given file is not completely NULL - this can happen if a
     * user drags & drops a folder onto a filemanager / filepicker element
     * @param string $filepath full path (including filename) to file to check
     * @return true if file has at least one non-null byte within it
     */
    protected function check_valid_contents($filepath) {
        $buffersize = 4096;

        $fp = fopen($filepath, 'r');
        if (!$fp) {
            return false; // Cannot read the file - something has gone wrong
        }
        while (!feof($fp)) {
            // Read the file 4k at a time
            $data = fread($fp, $buffersize);
            if (preg_match('/[^\0]+/', $data)) {
                fclose($fp);
                return true; // Return as soon as a non-null byte is found
            }
        }
        // Entire file is NULL
        fclose($fp);
        return false;
    }

    /**
     * Return a upload form
     * @return array
     */
    public function get_listing($path = '', $page = '') {
        global $CFG;
        $ret = array();
        $ret['nologin']  = true;
        $ret['nosearch'] = true;
        $ret['norefresh'] = true;
        $ret['list'] = array();
        $ret['dynload'] = false;
        $ret['upload'] = array('label'=>get_string('attachment', 'repository'), 'id'=>'repo-form');
        $ret['allowcaching'] = true; // indicates that result of get_listing() can be cached in filepicker.js
        return $ret;
    }

    /**
     * supported return types
     * @return int
     */
    public function supported_returntypes() {
        return (FILE_INTERNAL | FILE_EXTERNAL | FILE_REFERENCE);
    }
}
